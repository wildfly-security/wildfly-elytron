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

import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeFalse;
import static org.wildfly.security.tool.Command.isWindows;

import java.io.File;
import java.nio.file.Files;

import org.junit.BeforeClass;
import org.junit.AfterClass;
import org.junit.Test;
import org.junit.Assert;

/**
 * Tests related to Vault 2.0 -> credential store conversion.
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>
 */
public class VaultCommandTest extends AbstractCommandTest {

    private static final String TARGET_LOCATION = "./target";

    private static File workingDir = null;
    private static File credentialStoreFile1 = null;
    private static File credentialStoreFile2 = null;
    private static File credentialStoreFileMore = null;

    protected static final String SPECIAL_CHARS = "@!#?$^*{}%+-<>&|()/";
    protected static final String SPECIAL_CHARS_ENC_DIR = "target/test-classes/vault-v1/vault_data_special_chars/";
    protected static final String CHINESE_CHARS = "用戶名";
    protected static final String CHINESE_CHARS_ENC_DIR = "target/test-classes/vault-v1/vault_data_chinese_chars/";
    protected static final String ARABIC_CHARS = "اسمالمستخدم";
    protected static final String ARABIC_CHARS_ENC_DIR = "target/test-classes/vault-v1/vault_data_arabic_chars/";
    protected static final String JAPANESE_CHARS = "ユーザー名";
    protected static final String JAPANESE_CHARS_ENC_DIR = "target/test-classes/vault-v1/vault_data_japanese_chars/";

    private static final String ALIAS = "test";
    private static final String ENC_DIR = "target/test-classes/vault-v1/vault_data/";
    private static final String KEYSTORE = "target/test-classes/vault-v1/vault-jceks.keystore";
    private static final String KEYSTORE_PASSWORD = "secretsecret";
    private static final String SALT = "12345678";
    private static final String ITERATION = "34";
    private static final String MASK = "MASK-2hKo56F1a3jYGnJwhPmiF5";

    @BeforeClass
    public static void beforeTest() throws Exception {
        workingDir = new File(TARGET_LOCATION);
        if (workingDir.exists() == false) {
            workingDir.mkdirs();
        }

        credentialStoreFile1 = new File(workingDir, "v1-cs-1.store");
        credentialStoreFile2 = new File(workingDir, "v1-cs-2.store");
        credentialStoreFileMore = new File(workingDir, "v1-cs-more.store");
    }

    @AfterClass
    public static void afterTest() {
        if (workingDir != null) {
            workingDir.delete();
            workingDir = null;
        }
        if (credentialStoreFile1 != null) {
            credentialStoreFile1.delete();
            credentialStoreFile1 = null;
        }
        if (credentialStoreFile2 != null) {
            credentialStoreFile2.delete();
            credentialStoreFile2 = null;
        }
        if (credentialStoreFileMore != null) {
            credentialStoreFileMore.delete();
            credentialStoreFileMore = null;
        }
    }

    @Override
    protected String getCommandType() {
        return VaultCommand.VAULT_COMMAND;
    }

    /**
     * Single vault conversion test
     * @throws Exception when something ges wrong
     */
    @Test
    public void singleConversionBasicTest() throws Exception {
        String storeFileName = getStoragePathForNewFile();

        String[] args = new String[]{"--enc-dir", ENC_DIR, "--keystore", KEYSTORE,
                    "--keystore-password", MASK, "--salt", SALT, "--iteration", "34",
                    "--location", storeFileName, "--alias", ALIAS};
        // conversion
        executeVaultCommandWithParams(args);

        // check result
        args = new String[] { "--location", storeFileName, "--aliases", "--summary",
                "--password", "secretsecret"};

        String[] aliasesToCheck = {"vb1::attr11","vb1::attr12"};
        String output = executeCommandAndCheckStatusAndGetOutput(CredentialStoreCommand.CREDENTIAL_STORE_COMMAND, args);
        assertTrue(output.startsWith("Credential store contains following aliases:"));
        for (String aliasName : aliasesToCheck) {
            if (!output.contains(aliasName)) {
                Assert.fail(String.format("Credential store must contain aliasName [%s]. But output is [%s].",
                        aliasName, output));
            }
        }

    }

    /**
     * Two conversions to the same location test
     * @throws Exception
     */
    @Test
    public void singleConversionRewriteConvertedFileTest() throws Exception {
        // init
        String storeFileName = getStoragePathForNewFile();
        String[] args = new String[]{"--enc-dir", ENC_DIR, "--keystore", KEYSTORE,
                    "--keystore-password", MASK, "--salt", SALT, "--iteration", "34",
                    "--location", storeFileName, "--alias", ALIAS};
        // conversion
        executeVaultCommandWithParams(args);

        // check result
        String[] checkResultArgs = new String[] { "--location", storeFileName, "--aliases", "--summary",
                "--password", "secretsecret"};

        String[] aliasesToCheck = {"vb1::attr11","vb1::attr12"};
        String output = executeCommandAndCheckStatusAndGetOutput(CredentialStoreCommand.CREDENTIAL_STORE_COMMAND, checkResultArgs);
        assertTrue(output.startsWith("Credential store contains following aliases:"));
        for (String aliasName : aliasesToCheck) {
            if (!output.contains(aliasName)) {
                Assert.fail(String.format("Credential store must contain aliasName [%s]. But output is [%s].",
                        aliasName, output));
            }
        }

        // convert again - it must fail because of same storeFileName
        executeVaultCommandWithParams(args, false,
                String.format("java.lang.IllegalArgumentException: ELYTOOL00026: Credential store storage file \"%s\" already exists.",
                storeFileName));
    }

    /**
     * Conversion with empty encryption directory test
     * @throws Exception
     */
    @Test
    public void testEmptyEncDirFolder() throws Exception {
        String storeFileName = getStoragePathForNewFile();
        String emptyEncDirFolder = Files.createTempDirectory("testEmptyEncDirFolder").toAbsolutePath().toString();

        String[] args = new String[]{"--enc-dir", emptyEncDirFolder, "--keystore", KEYSTORE,
                "--keystore-password", MASK, "--salt", SALT, "--iteration", "34",
                "--location", storeFileName, "--alias", "test"};
        executeVaultCommandWithParams(args, false, "ELYTOOL00019");
    }

    /**
     * Conversion with special characters test
     * @throws Exception
     */
    @Test
    public void specialCharsTest() throws Exception {
        // init
        String storeFileName = getStoragePathForNewFile();
        String[] args = new String[]{"--enc-dir", SPECIAL_CHARS_ENC_DIR, "--keystore", KEYSTORE,
                    "--keystore-password", MASK, "--salt", SALT, "--iteration", "34",
                    "--location", storeFileName, "--alias", ALIAS};
        executeVaultCommandWithParams(args);

        // check result
        String[] checkResultArgs = new String[] { "--location", storeFileName, "--aliases", "--summary",
                "--password", "secretsecret"};

        String[] aliasesToCheck = {"sc1::" + SPECIAL_CHARS, SPECIAL_CHARS + "::sc11", "sc2::sc12", SPECIAL_CHARS + "::" + SPECIAL_CHARS };
        String output = executeCommandAndCheckStatusAndGetOutput(CredentialStoreCommand.CREDENTIAL_STORE_COMMAND, checkResultArgs);
        assertTrue(output.startsWith("Credential store contains following aliases:"));
        for (String aliasName : aliasesToCheck) {
            if (!output.contains(aliasName)) {
                Assert.fail(String.format("Credential store must contain aliasName [%s]. But output is [%s].",
                        aliasName, output));
            }
        }
    }

    /**
     * Conversion with chinese characters test
     * @throws Exception
     */
    @Test
    public void chineseCharsTest() throws Exception {
        assumeFalse("https://issues.redhat.com/browse/ELY-2245", isWindows());
        // init
        String storeFileName = getStoragePathForNewFile();
        String[] args = new String[]{"--enc-dir", CHINESE_CHARS_ENC_DIR, "--keystore", KEYSTORE,
                    "--keystore-password", MASK, "--salt", SALT, "--iteration", "34",
                    "--location", storeFileName, "--alias", ALIAS};
        executeVaultCommandWithParams(args);

        // check result
        String[] checkResultArgs = new String[] { "--location", storeFileName, "--aliases", "--summary",
                "--password", "secretsecret"};

        String[] aliasesToCheck = {"cn1::" + CHINESE_CHARS, CHINESE_CHARS + "::cn11", "cn2::cn12", CHINESE_CHARS + "::" + CHINESE_CHARS };
        String output = executeCommandAndCheckStatusAndGetOutput(CredentialStoreCommand.CREDENTIAL_STORE_COMMAND, checkResultArgs);
        assertTrue(output.startsWith("Credential store contains following aliases:"));
        for (String aliasName : aliasesToCheck) {
            if (!output.contains(aliasName)) {
                Assert.fail(String.format("Credential store must contain aliasName [%s]. But output is [%s].",
                        aliasName, output));
            }
        }
    }

    /**
     * Conversion with arabic characters test
     * @throws Exception
     */
    @Test
    public void arabicCharsTest() throws Exception {
        assumeFalse("https://issues.redhat.com/browse/ELY-2245", isWindows());
        // init
        String storeFileName = getStoragePathForNewFile();
        String[] args = new String[]{"--enc-dir", ARABIC_CHARS_ENC_DIR, "--keystore", KEYSTORE,
                    "--keystore-password", MASK, "--salt", SALT, "--iteration", "34",
                    "--location", storeFileName, "--alias", ALIAS};
        executeVaultCommandWithParams(args);

        // check result
        String[] checkResultArgs = new String[] { "--location", storeFileName, "--aliases", "--summary",
                "--password", "secretsecret"};

        String[] aliasesToCheck = {"ar1::" + ARABIC_CHARS, ARABIC_CHARS + "::ar11", "ar2::ar12", ARABIC_CHARS + "::" + ARABIC_CHARS };
        String output = executeCommandAndCheckStatusAndGetOutput(CredentialStoreCommand.CREDENTIAL_STORE_COMMAND, checkResultArgs);
        assertTrue(output.startsWith("Credential store contains following aliases:"));
        for (String aliasName : aliasesToCheck) {
            if (!output.contains(aliasName)) {
                Assert.fail(String.format("Credential store must contain aliasName [%s]. But output is [%s].",
                        aliasName, output));
            }
        }
    }

    /**
     * Conversion with japanese characters test
     * @throws Exception
     */
    @Test
    public void japaneseCharsTest() throws Exception {
        assumeFalse("https://issues.redhat.com/browse/ELY-2245", isWindows());
        // init
        String storeFileName = getStoragePathForNewFile();
        String[] args = new String[]{"--enc-dir", JAPANESE_CHARS_ENC_DIR, "--keystore", KEYSTORE,
                    "--keystore-password", MASK, "--salt", SALT, "--iteration", "34",
                    "--location", storeFileName, "--alias", ALIAS};
        executeVaultCommandWithParams(args);

        // check result
        String[] checkResultArgs = new String[] { "--location", storeFileName, "--aliases", "--summary",
                "--password", "secretsecret"};

        String[] aliasesToCheck = {"jp1::" + JAPANESE_CHARS, JAPANESE_CHARS + "::jp11", "jp2::jp12", JAPANESE_CHARS + "::" + JAPANESE_CHARS };
        String output = executeCommandAndCheckStatusAndGetOutput(CredentialStoreCommand.CREDENTIAL_STORE_COMMAND, checkResultArgs);
        assertTrue(output.startsWith("Credential store contains following aliases:"));
        for (String aliasName : aliasesToCheck) {
            if (!output.contains(aliasName)) {
                Assert.fail(String.format("Credential store must contain aliasName [%s]. But output is [%s].",
                        aliasName, output));
            }
        }
    }

    /**
     * Invalid parameters test
     * @throws Exception
     */
    @Test
    public void singleConversionInvalidRequiredOptionTest() throws Exception {
        executeVaultCommandWithParams(("--alias wrongAliasName --keystore-password " + KEYSTORE_PASSWORD + " --enc-dir " + ENC_DIR + " --keystore " + KEYSTORE + " --location any").split(" "),
                false, "ELYTOOL00008: Cannot locate admin key with alias \"wrongAliasName\" or it is of improper type");
        executeVaultCommandWithParams(("--alias " + ALIAS + " --keystore-password invalid_password --enc-dir " + ENC_DIR + " --keystore " + KEYSTORE + " --location any").split(" "),
                false, "Keystore was tampered with, or password was incorrect");
        executeVaultCommandWithParams(("--alias " + ALIAS + " --keystore-password " + KEYSTORE_PASSWORD + " --enc-dir wrongEncDirName --keystore " + KEYSTORE + " --location any").split(" "),
                false, "ELYTOOL00019: Encryption directory \"wrongEncDirName\" does not contain \"VAULT.dat\" file");
        executeVaultCommandWithParams(("--alias " + ALIAS + " --keystore-password " + KEYSTORE_PASSWORD + " --enc-dir " + ENC_DIR + " --keystore wrongKsPath --location any").split(" "),
                false,  "java.io.FileNotFoundException: wrongKsPath ");
    }

    /**
     * Salt and iteration parameters test
     * @throws Exception
     */
    @Test
    public void testConvertOperationSaltAndIteration() throws Exception {
        String baseCommand = "--enc-dir " + ENC_DIR + " --keystore " + KEYSTORE + " --keystore-password " + MASK + " --alias " + ALIAS;

        executeVaultCommandWithParams((baseCommand + " --location " + getStoragePathForNewFile() + " --salt 12345678 --iteration 34").split(" "), true);
        executeVaultCommandWithParams((baseCommand + " --location " + getStoragePathForNewFile() + " --salt --iteration 34").split(" "),
                false, "Missing argument for option: s");
        executeVaultCommandWithParams((baseCommand + " --location " + getStoragePathForNewFile() + " --salt 1234567890 --iteration 34").split(" "),
                false,"Salt must be 8 bytes long");
        executeVaultCommandWithParams((baseCommand + " --location " + getStoragePathForNewFile() + " --salt 12345678 --iteration abcd").split(" "),
                false, "NumberFormatException");
    }

    /**
     * Help option test
     * @throws Exception
     */
    @Test
    public void testHelp() throws Exception {
        executeVaultCommandWithParams(new String[]{"--help"}, true, "command is used convert PicketBox Security Vault to credential store");
    }

    /**
     * Summary option test
     * @throws Exception
     */
    @Test
    public void singleConversionSummaryTest() throws Exception {
        String storeFileName = getStoragePathForNewFile();

        String[] args = new String[]{"--enc-dir", ENC_DIR, "--keystore", KEYSTORE,
                    "--keystore-password", KEYSTORE_PASSWORD,
                    "--location", storeFileName, "--alias", ALIAS, "--summary"};

        String expectedSummary = String.format(
                "/subsystem=elytron/credential-store=test:add(relative-to=jboss.server.data.dir,create=true,modifiable=true,location=\"%s\","
                        + "implementation-properties={\"keyStoreType\"=>\"JCEKS\"},credential-reference={clear-text=\"%s\"})",
                storeFileName, "MASK-13KrO2ZNhwNg3UxmIt.02D;12345678;23");

        // conversion
        executeVaultCommandWithParams(args, true, expectedSummary);
    }

    /**
     * Summary option test with masked password
     * @throws Exception
     */
    @Test
    public void singleConversionSummaryMaskedPasswordTest() throws Exception {
        String storeFileName = getStoragePathForNewFile();

        String[] args = new String[]{"--enc-dir", ENC_DIR, "--keystore", KEYSTORE,
                    "--keystore-password", MASK, "--salt", SALT, "--iteration", "34",
                    "--location", storeFileName, "--alias", ALIAS, "--summary"};

        String expectedSummary = String.format(
                "/subsystem=elytron/credential-store=test:add(relative-to=jboss.server.data.dir,create=true,modifiable=true,location=\"%s\","
                        + "implementation-properties={\"keyStoreType\"=>\"JCEKS\"},credential-reference={clear-text=\"%s\"})",
                storeFileName, MASK + ";" + SALT + ";" + ITERATION);

        // Conversion
        executeVaultCommandWithParams(args, true, expectedSummary);
    }

    /**
     * Bulk vault conversion test
     * @throws Exception when something ges wrong
     */
    @Test
    public void bulkConversionBasicTest() throws Exception {
        String[] args = new String[]{"--bulk-convert", "target/test-classes/bulk-vault-conversion-desc"};
        // conversion
        String output = executeCommandAndCheckStatusAndGetOutput(args);
        String[] parts = output.split("converted to credential store");
        Assert.assertTrue("Three credential stores has to be created", parts.length == 4);
        Assert.assertTrue("Check file names must pass", output.indexOf("vault-v1/vault-jceks.keystore") > 0 && output.indexOf("vault-v1-more/vault-jceks.keystore") > 0);

        // check result
        args = new String[] { "--location", "target/v1-cs-more.store" , "--aliases", "--summary",
                "--password", "secretsecret"};
        String[] aliasesToCheck = {"vb1::attr11","vb1::attr12"};
        output = executeCommandAndCheckStatusAndGetOutput(CredentialStoreCommand.CREDENTIAL_STORE_COMMAND, args);
        assertTrue(output.startsWith("Credential store contains following aliases:"));
        for (String aliasName : aliasesToCheck) {
            if (!output.contains(aliasName)) {
                Assert.fail(String.format("Credential store must contain aliasName [%s]. But output is [%s].",
                        aliasName, output));
            }
        }

    }

    /**
     * Bulk vault conversion test with wrong option
     * @throws Exception when something goes wrong
     */
    @Test
    public void bulkConversionWrongOption() {
        String[] args = {"--bulk-convert", "target/test-classes/bulk-vault-conversion-desc", "--location", "target/v1-cs-more.store"};
        executeVaultCommandWithParams(args, false, "ELYTOOL00013");
    }

    /**
     * Bulk vault conversion test with wrong order
     * @throws Exception when something ges wrong
     */
    @Test
    public void bulkConversionDecsFileWrongOrder() throws Exception {
        String[] args = {"--bulk-convert", "target/test-classes/bulk-vault-conversion-wrong-order"};
        executeVaultCommandWithParams(args, false);
    }

    /**
     * Duplicated options test
     */
    @Test
    public void testDuplicateOptions() {
        String storeFileName = getStoragePathForNewFile();

        String[] args = new String[]{"--enc-dir", ENC_DIR, "--keystore", KEYSTORE, "--keystore-password", MASK, "--salt", SALT, "--iteration", "34",
                    "--location", storeFileName, "--alias", ALIAS, "-e", "dir", "--keystore", "store"};

        String output = executeCommandAndCheckStatusAndGetOutput(args);

        Assert.assertTrue(output.contains("Option \"enc-dir\" specified more than once. Only the first occurrence will be used."));
        Assert.assertTrue(output.contains("Option \"keystore\" specified more than once. Only the first occurrence will be used."));
        Assert.assertFalse(output.contains("Option \"salt\" specified more than once. Only the first occurrence will be used"));
    }

    /**
     * Bulk vault conversion missing the alias option
     */
    @Test
    public void bulkConversionMissingAliasOption() {
        String[] args = {"--bulk-convert", "target/test-classes/bulk-vault-conversion-no-alias"};
        executeVaultCommandWithParams(args, false, "ELYTOOL00020");
    }

    /**
     * Bulk vault conversion missing the location option
     */
    @Test
    public void bulkConversionMissingLocationOption() {
        String[] args = {"--bulk-convert", "target/test-classes/bulk-vault-conversion-no-location"};
        executeVaultCommandWithParams(args, false, "ELYTOOL00021");
    }

    /**
     * Bulk vault conversion missing the enc-dir option
     */
    @Test
    public void bulkConversionMissingEncryptionDirOption() {
        String[] args = {"--bulk-convert", "target/test-classes/bulk-vault-conversion-no-enc-dir"};
        executeVaultCommandWithParams(args, false, "ELYTOOL00022");
    }

    /**
     * Bulk vault conversion missing the keystore-password option
     */
    @Test
    public void bulkConversionMissingKeystorePasswordOption() {
        String[] args = {"--bulk-convert", "target/test-classes/bulk-vault-conversion-no-keystore-password"};
        executeVaultCommandWithParams(args, false, "ELYTOOL00023");
    }

    /**
     * Bulk vault conversion missing the keystore option
     */
    @Test
    public void bulkConversionMissingKeystoreOption() {
        String[] args = {"--bulk-convert", "target/test-classes/bulk-vault-conversion-no-keystore-url"};
        executeVaultCommandWithParams(args, false, "ELYTOOL00024");
    }

    private void executeVaultCommandWithParams(String[] args) {
        executeVaultCommandWithParams(args, true);
    }

    private void executeVaultCommandWithParams(String[] args, boolean shouldPass) {
        executeVaultCommandWithParams(args, shouldPass, null);
    }

    private void executeVaultCommandWithParams(String[] args, boolean shouldPass, String expectedOutput) {
        boolean passed = false;
        String output;

        try {
            output = executeCommandAndCheckStatusAndGetOutput(args);
            passed = true;
        } catch (RuntimeException e) {
            output = e.getMessage();
            if (e.getCause().getCause() != null) {
                output += e.getCause().getCause().getMessage();
            }
        }

        String message = "Execution of vault command with arguments {" + String.join(" ", args) + "} should" +
                (shouldPass? " succeeded ": " failed ") + "but it" + (shouldPass? " failed": " succeeded");
        Assert.assertEquals(message, shouldPass, passed);

        if (expectedOutput != null) {
            Assert.assertTrue("Command output should contain \"" + expectedOutput + "\"", output.contains(expectedOutput));
        }
    }
}