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

import java.io.File;

import org.junit.BeforeClass;
import org.junit.AfterClass;
import org.junit.Test;
import org.junit.Assert;

/**
 * Tests related to Vault 2.0 -> credential store conversion.
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>
 */
public class VaultCommandTest extends AbstractCommandTest {
    private static final boolean IS_IBM = System.getProperty("java.vendor").contains("IBM");

    private static final String TARGET_LOCATION = "./target";

    private static File workingDir = null;
    private static File credentialStoreFile1 = null;
    private static File credentialStoreFile2 = null;
    private static File credentialStoreFileMore = null;

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

        String[] args;
        if (IS_IBM) {
            args = new String[]{"--enc-dir", "target/test-classes/vault-v1/vault_data_ibm/", "--keystore", "target/test-classes/vault-v1/vault-jceks-ibm.keystore",
                    "--keystore-password", "MASK-2hKo56F1a3jYGnJwhPmiF5", "--salt", "12345678", "--iteration", "34",
                    "--location", storeFileName, "--alias", "test"};
        } else {
            args = new String[]{"--enc-dir", "target/test-classes/vault-v1/vault_data/", "--keystore", "target/test-classes/vault-v1/vault-jceks.keystore",
                    "--keystore-password", "MASK-2hKo56F1a3jYGnJwhPmiF5", "--salt", "12345678", "--iteration", "34",
                    "--location", storeFileName, "--alias", "test"};
        }
        // conversion
        executeCommandAndCheckStatus(args);

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
     * Bulk vault conversion test
     * @throws Exception when something ges wrong
     */
    @Test
    public void bulkConversionBasicTest() throws Exception {
        String[] args;
        if (IS_IBM) {
            args = new String[]{"--bulk-convert", "target/test-classes/bulk-vault-conversion-desc-ibm"};
        } else {
            args = new String[]{"--bulk-convert", "target/test-classes/bulk-vault-conversion-desc"};
        }
        // conversion
        String output = executeCommandAndCheckStatusAndGetOutput(args);
        String[] parts = output.split("converted to credential store");
        Assert.assertTrue("Three credential stores has to be created", parts.length == 4);
        if (IS_IBM) {
            Assert.assertTrue("Check file names must pass", output.indexOf("vault-v1/vault-jceks-ibm.keystore") > 0 && output.indexOf("vault-v1-more/vault-jceks-ibm.keystore") > 0);
        } else {
            Assert.assertTrue("Check file names must pass", output.indexOf("vault-v1/vault-jceks.keystore") > 0 && output.indexOf("vault-v1-more/vault-jceks.keystore") > 0);
        }


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
        try {
            executeCommandAndCheckStatus(args);
        } catch (Exception e) {
            Assert.assertTrue(e.getCause().getMessage().contains("ELYTOOL00013")
                && e.getCause().getMessage().indexOf("location") > -1);
        }
    }

    @Test
    public void testDuplicateOptions() {
        String storeFileName = getStoragePathForNewFile();

        String[] args;
        if (IS_IBM) {
            args = new String[]{"--enc-dir", "target/test-classes/vault-v1/vault_data_ibm/", "--keystore", "target/test-classes/vault-v1/vault-jceks-ibm.keystore", "--keystore-password", "MASK-2hKo56F1a3jYGnJwhPmiF5", "--salt", "12345678", "--iteration", "34",
                    "--location", storeFileName, "--alias", "test", "-e", "dir", "--keystore", "store"};
        } else {
            args = new String[]{"--enc-dir", "target/test-classes/vault-v1/vault_data/", "--keystore", "target/test-classes/vault-v1/vault-jceks.keystore", "--keystore-password", "MASK-2hKo56F1a3jYGnJwhPmiF5", "--salt", "12345678", "--iteration", "34",
                    "--location", storeFileName, "--alias", "test", "-e", "dir", "--keystore", "store"};
        }

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
        boolean testFailed = true;
        try {
            executeCommandAndCheckStatus(args);
        } catch (Exception e) {
            // Exception is wrapped inside ELYTOOL00012
            Assert.assertTrue(e.getCause().getCause().getMessage().contains("ELYTOOL00020"));
            testFailed = false;
        }

        Assert.assertFalse("Test was supposed to throw exception!", testFailed);
    }

    /**
     * Bulk vault conversion missing the location option
     */
    @Test
    public void bulkConversionMissingLocationOption() {
        String[] args = {"--bulk-convert", "target/test-classes/bulk-vault-conversion-no-location"};
        boolean testFailed = true;
        try {
            executeCommandAndCheckStatus(args);
        } catch (Exception e) {
            // Exception is wrapped inside ELYTOOL00012
            Assert.assertTrue(e.getCause().getCause().getMessage().contains("ELYTOOL00021"));
            testFailed = false;
        }

        Assert.assertFalse("Test was supposed to throw exception!", testFailed);
    }

    /**
     * Bulk vault conversion missing the enc-dir option
     */
    @Test
    public void bulkConversionMissingEncryptionDirOption() {
        String[] args = {"--bulk-convert", "target/test-classes/bulk-vault-conversion-no-enc-dir"};
        boolean testFailed = true;
        try {
            executeCommandAndCheckStatus(args);
        } catch (Exception e) {
            // Exception is wrapped inside ELYTOOL00012
            Assert.assertTrue(e.getCause().getCause().getMessage().contains("ELYTOOL00022"));
            testFailed = false;
        }

        Assert.assertFalse("Test was supposed to throw exception!", testFailed);
    }

    /**
     * Bulk vault conversion missing the keystore-password option
     */
    @Test
    public void bulkConversionMissingKeystorePasswordOption() {
        String[] args = {"--bulk-convert", "target/test-classes/bulk-vault-conversion-no-keystore-password"};
        boolean testFailed = true;
        try {
            executeCommandAndCheckStatus(args);
        } catch (Exception e) {
            // Exception is wrapped inside ELYTOOL00012
            Assert.assertTrue(e.getCause().getCause().getMessage().contains("ELYTOOL00023"));
            testFailed = false;
        }

        Assert.assertFalse("Test was supposed to throw exception!", testFailed);
    }

    /**
     * Bulk vault conversion missing the keystore option
     */
    @Test
    public void bulkConversionMissingKeystoreOption() {
        String[] args = {"--bulk-convert", "target/test-classes/bulk-vault-conversion-no-keystore-url"};
        boolean testFailed = true;
        try {
            executeCommandAndCheckStatus(args);
        } catch (Exception e) {
            testFailed = false;
            Assert.assertTrue(e.getCause().getMessage().contains("ELYTOOL00024"));
            testFailed = false;
        }

        Assert.assertFalse("Test was supposed to throw exception!", testFailed);
    }
}
