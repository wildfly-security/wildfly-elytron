/*
 * JBoss, Home of Professional Open Source
 * Copyright 2017 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.wildfly.security.tool;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.apache.commons.cli.AlreadySelectedException;
import org.apache.commons.lang3.tuple.Pair;
import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;
import org.wildfly.security.credential.store.CredentialStore;
import org.wildfly.security.credential.store.CredentialStoreException;

/**
 * Test for "credential-store" command.
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>
 * @author Hynek Švábek <hsvabek@redhat.com>
 */
public class CredentialStoreCommandTest extends AbstractCommandTest {

    @Override
    protected String getCommandType() {
        return CredentialStoreCommand.CREDENTIAL_STORE_COMMAND;
    }

    /**
     * basic test with --password option.
     */
    @Test
    public void clearTextCSPassword() {
        String storeFileName = getStoragePathForNewFile();

        String[] args = {"--location=" + storeFileName, "--create",
                "--add", "testalias", "--secret", "secret2", "--summary", "--password", "cspassword"};
        executeCommandAndCheckStatus(args);
    }

    /**
     * basic test with --password and masking password options.
     * @throws Exception if something goes wrong
     */
    @Test
    public void maskCSPassword() {
        String storeFileName = getStoragePathForNewFile();

        String[] args = {"--location=" + storeFileName, "--create",
                "--add", "testalias", "--secret", "secret2", "--summary", "--password", "cspassword", "--salt", "A1B2C3D4", "--iteration", "100"};

        String output = executeCommandAndCheckStatusAndGetOutput(args);
        assertTrue(output.contains("MASK-"));
    }

    /**
     * basic test without --password option.
     * @throws Exception if something goes wrong
     */
    @Ignore("Issue #15 - bypass prompting using callback handler")
    @Test(expected = CredentialStoreException.class)
    public void noPasswordSpecified() throws Exception {
        ElytronTool tool = new ElytronTool();
        Command command = tool.findCommand(CredentialStoreCommand.CREDENTIAL_STORE_COMMAND);

        String storeFileName = getStoragePathForNewFile();

        String[] args = {"--location=" + storeFileName, "--create",
                "--add", "testalias", "--secret", "secret2", "--summary", "--salt", "A1B2C3D4", "--iteration", "100"};

        command.execute(args);
    }

    @Test
    public void testAddAlias() {
        String storageLocation = getStoragePathForNewFile();
        String storagePassword = "cspassword";
        String aliasName = "testalias";
        String aliasValue = "secret2";

        String[] args = { "--location=" + storageLocation, "--create", "--add", aliasName, "--secret",
                aliasValue, "--summary", "--password", storagePassword };
        executeCommandAndCheckStatus(args);

        CredentialStore store = getCredentialStoreStorageFromExistsFile(storageLocation, storagePassword);
        checkAliasSecretValue(store, aliasName, aliasValue);
    }

    @Test
    public void testAliasesList() {
        String storageLocation = getStoragePathForNewFile();
        String storagePassword = "cspassword";
        String[] aliasNames = { "testalias1", "testalias2", "testalias3" };
        String[] aliasValues = {"secret1", "secret2", "secret3"};

        for (int i = 0; i < aliasNames.length; i++) {
            try {
                createStoreAndAddAliasAndCheck(storageLocation, storagePassword, aliasNames[i], aliasValues[i]);
            } catch (RuntimeException e) {
                if (!(e.getCause() instanceof NullPointerException)) {
                    Assert.fail("It must fail because of there is forbidden to use empty alias name or value.");
                }
            }
        }

        String[] args = new String[] { "--location=" + storageLocation, "--create", "--aliases", "--summary",
                "--password", storagePassword, "--properties", "keyStoreType=JCEKS;keyAlias=not_relevant"};
        executeCommandAndCheckStatus(args);

        String output = executeCommandAndCheckStatusAndGetOutput(args);
        assertTrue(output.startsWith("Credential store contains following aliases:"));
        for (String aliasName : aliasNames) {
            if (!output.contains(aliasName)) {
                Assert.fail(String.format("Credential store must contain aliasName [%s]. But output is [%s].",
                    aliasName, output));
            }
        }
    }

    @Test
    public void testRemoveAlias() {
        String storageLocation = getStoragePathForNewFile();
        String storagePassword = "cspassword";
        String aliasName = "testalias";
        String aliasValue = "secret2";

        String[] args = { "--location=" + storageLocation, "--create", "--add", aliasName, "--secret",
                aliasValue, "--summary", "--password", storagePassword };
        executeCommandAndCheckStatus(args);
        CredentialStore store = getCredentialStoreStorageFromExistsFile(storageLocation, storagePassword);
        checkAliasSecretValue(store, aliasName, aliasValue);

        args = new String[] { "--location=" + storageLocation, "--create", "--remove", aliasName,
                "--summary", "--password", storagePassword };
        executeCommandAndCheckStatus(args);
        store = getCredentialStoreStorageFromExistsFile(storageLocation, storagePassword);
        checkNonExistsAlias(store, aliasName);
    }

    @Test
    public void testUpdateAlias() {
        String storageLocation = getStoragePathForNewFile();
        String storagePassword = "cspassword";
        String aliasName = "testalias";
        String aliasValue = "secret2";
        String aliasNewSecretValue = "updatedSecretValue";

        String[] args = { "--location=" + storageLocation, "--create", "--add", aliasName, "--secret",
                aliasValue, "--summary", "--password", storagePassword };
        executeCommandAndCheckStatus(args);
        CredentialStore store = getCredentialStoreStorageFromExistsFile(storageLocation, storagePassword);
        checkAliasSecretValue(store, aliasName, aliasValue);

        args = new String[] { "--location=" + storageLocation, "--create", "--add", aliasName,
                "--secret", aliasNewSecretValue, "--summary", "--password", storagePassword };
        executeCommandAndCheckStatus(args);
        store = getCredentialStoreStorageFromExistsFile(storageLocation, storagePassword);
        checkAliasSecretValue(store, aliasName, aliasNewSecretValue);
    }

    @Test
    public void testExistsAlias() {
        String storageLocation = getStoragePathForNewFile();
        String storagePassword = "cspassword";
        String aliasName = "testalias";
        String aliasValue = "secret2";

        String[] args = { "--location=" + storageLocation, "--create", "--add", aliasName, "--secret",
                aliasValue, "--summary", "--password", storagePassword };
        executeCommandAndCheckStatus(args);
        CredentialStore store = getCredentialStoreStorageFromExistsFile(storageLocation, storagePassword);
        checkAliasSecretValue(store, aliasName, aliasValue);

        args = new String[] { "--location=" + storageLocation, "--create", "--exists", aliasName,
                "--summary", "--password", storagePassword };
        executeCommandAndCheckStatus(args);
        store = getCredentialStoreStorageFromExistsFile(storageLocation, storagePassword);
        checkExistsAlias(store, aliasName);
    }

    @Test
    public void testMaskedPassword() {
        String clearTextPassword = "secret_password";
        String expectedMaskedPassword = "MASK-1GhfMaq4jSY0.kFFU3QG4T";
        String salt = "12345678";
        String iteration = "230";

        String storeFileName = getStoragePathForNewFile();

        String[] args = { "--location=" + storeFileName, "--create", "--add", "testalias", "--secret",
                "secret2", "--summary", "--password", clearTextPassword, "--salt", salt, "--iteration", iteration };

        String output = executeCommandAndCheckStatusAndGetOutput(args);
        assertTrue(output.contains(expectedMaskedPassword + ";" + salt + ";" + iteration));
    }

    @Test
    @Ignore("https://issues.jboss.org/browse/ELY-1035")
    public void testMutuallyExclusiveArgs() {
        ElytronTool tool = new ElytronTool();
        Command command = tool.findCommand(CredentialStoreCommand.CREDENTIAL_STORE_COMMAND);

        String clearTextPassword = "secret_password";

        Pair<String, String> addOperation = Pair.of("--add", "-a");
        Pair<String, String> existsOperation = Pair.of("--exists", "-e");
        Pair<String, String> removeOperation = Pair.of("--remove", "-r");
        Pair<String, String> aliasesOperation = Pair.of("--aliases", "-v");

        String storeFileName = getStoragePathForNewFile();
        String[] firstOperation = { addOperation.getLeft(), addOperation.getRight(), existsOperation.getLeft(),
                aliasesOperation.getLeft(), aliasesOperation.getRight() };
        String[] secondOperation = { removeOperation.getRight(), removeOperation.getLeft(), addOperation.getLeft(),
                removeOperation.getLeft(), addOperation.getRight() };

        for (int i = 0; i < firstOperation.length; i++) {
            String[] args = { "--location=" + storeFileName, "--create", firstOperation[i],
                    "testalias", "--secret", "secret2", "--summary", "--password", clearTextPassword,
                    secondOperation[i] };
            try {
                command.execute(args);
                Assert.fail("We expect fail.");
            } catch (Exception e) {
                if (!(e instanceof AlreadySelectedException)) {
                    Assert.fail(String.format("We expect different exception [%s], but we get [%s]",
                        AlreadySelectedException.class.getSimpleName(), e.getClass().getSimpleName()));
                }
                assertEquals(
                    String.format("The option '%s' was specified but an option from this group has already been selected: '%s'",
                        secondOperation[i], firstOperation[i]), e.getMessage());
            }
        }
    }

    @Test
    @Ignore("https://issues.jboss.org/browse/ELY-1036")
    public void testMultiRequiredOption() {
        ElytronTool tool = new ElytronTool();
        Command command = tool.findCommand(CredentialStoreCommand.CREDENTIAL_STORE_COMMAND);

        String clearTextPassword = "secret_password";

        String storeFileName = getStoragePathForNewFile();
        String longOperation = "add";
        String shortOperation = "a";

        String[] args = { "--location=" + storeFileName, "--create", "--" + longOperation, "testalias",
                "--secret", "secret2", "--summary", "--password", clearTextPassword, "-" + shortOperation, "doesnt_matter" };
        try {
            command.execute(args);
            Assert.fail("We expect fail.");
        } catch (Exception e) {
            if (!(e instanceof AlreadySelectedException)) {
                Assert.fail(String.format("We expect different exception [%s], but we get [%s]",
                    AlreadySelectedException.class.getSimpleName(), e.getClass().getSimpleName()));
            }
            assertEquals(
                String.format("FIX THIS CONDITION once the bug is fixed. '%s', '%s'", shortOperation, longOperation),
                e.getMessage());
        }
    }

    @Test
    @Ignore("https://issues.jboss.org/browse/ELY-1037"
    + "https://issues.jboss.org/browse/ELY-890")
    public void testLocationFromUri() {
        String clearTextPassword = "secret_password";
        String aliasName = "aliasName";

        String storeFileName = "test.jceks";
        String longOperation = "add";

        String[] args = { "--uri=cr-store://" + storeFileName + "?create=true", "--" + longOperation, aliasName,
                "--secret", "secret2", "--summary", "--password", clearTextPassword };

        executeCommandAndCheckStatus(args);

        CredentialStore store = getCredentialStoreStorageFromExistsFile(storeFileName, clearTextPassword);
        checkExistsAlias(store, aliasName);
    }

    @Test
    public void testPrintHelp() {
        String clearTextPassword = "secret_password";
        String storeFileName = getStoragePathForNewFile();
        assertTrue(executeCommandAndCheckStatusAndGetOutput(new String[]{"--help",  "--location=" + storeFileName, "--create", "--summary", "--password", clearTextPassword, "-a", "alias1", "-x", "secret1" })
            .contains("Get help with usage of this command"));
        assertTrue(executeCommandAndCheckStatusAndGetOutput(new String[]{"--help"})
                .contains("Get help with usage of this command"));

    }

    @Test
    @Ignore("https://issues.jboss.org/browse/ELY-1033")
    public void testShowHelpWithPriority() {
        String clearTextPassword = "secret_password";

        String storeFileName = getStoragePathForNewFile();

        String[] args = { "--location=" + storeFileName, "--create", "--add", "testalias", "--secret",
                "secret2", "--summary", "--password", clearTextPassword, "--help" };

        String output = executeCommandAndCheckStatusAndGetOutput(args);
        assertTrue(output.contains("Get help with usage of this command"));
    }

    @Test
    @Ignore("https://issues.jboss.org/browse/WFCORE-2480")
    public void testCreateEmptyStore() {
        String clearTextPassword = "secret_password";
        String aliasName = "aliasName";

        String storeFileName = getStoragePathForNewFile();
        String longOperation = "create-storage";

        String[] args = { "--uri=cr-store://" + storeFileName + "?create=true", "--" + longOperation, "--summary", "--password",
                clearTextPassword };

        executeCommandAndCheckStatus(args);

        CredentialStore store = getCredentialStoreStorageFromExistsFile(storeFileName, clearTextPassword);
        // write alias to store... (if backed file exists it will pass)
        try {
            store.store(aliasName, createCredentialFromPassword("aliasSecretValue".toCharArray()));
            store.flush();
        } catch (Exception e) {
            Assert.fail(e.getMessage());
        }
    }

    @Test
    public void testDuplicateOptions() {
        String storageLocation = getStoragePathForNewFile();
        String storagePassword = "cspassword";
        String aliasName = "testalias";
        String aliasValue = "secret2";

        String[] args = { "--location=" + storageLocation, "--create", "--add", aliasName, "--secret", aliasValue, "--summary",
                "--password", storagePassword, "--add", "another_alias", "-x", "another_secret" };
        String output = executeCommandAndCheckStatusAndGetOutput(args);

        Assert.assertTrue(output.contains("Option \"add\" specified more than once. Only the first occurrence will be used."));
        Assert.assertTrue(output.contains("Option \"secret\" specified more than once. Only the first occurrence will be used."));
        Assert.assertFalse(output.contains("Option \"create\" specified more than once. Only the first occurrence will be used"));
    }
}
