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

import org.junit.Assert;
import org.junit.Test;

/**
 * Tests related to Vault 2.0 -> credential store conversion.
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>
 */
public class VaultCommandTest extends AbstractCommandTest {


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

        String[] args = {"--enc-dir", "target/test-classes/vault-v1/vault_data/", "--keystore", "target/test-classes/vault-v1/vault-jceks.keystore", "--keystore-password", "MASK-2hKo56F1a3jYGnJwhPmiF5", "--salt", "12345678", "--iteration", "34",
                "--location", storeFileName, "--alias", "test"};
        // conversion
        executeCommandAndCheckStatus(args);

        // check result
        args = new String[] { "--location", storeFileName, "--uri", "cr-store://test", "--aliases", "--summary",
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
        String[] args = {"--bulk-convert", "target/test-classes/bulk-vault-conversion-desc"};
        // conversion
        String output = executeCommandAndCheckStatusAndGetOutput(args);
        String[] parts = output.split("converted to credential store");
        Assert.assertTrue("Three credential stores has to be created", parts.length == 4);
        Assert.assertTrue("Check file names must pass", output.indexOf("vault-v1/vault-jceks.keystore") > 0 && output.indexOf("vault-v1-more/vault-jceks.keystore") > 0);

        // check result
        args = new String[] { "--location", "target/v1-cs-more.store" , "--uri", "cr-store://test", "--aliases", "--summary",
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
     * @throws Exception when something ges wrong
     */
    @Test
    public void bulkConversionWrongOption() {
        String[] args = {"--bulk-convert", "target/test-classes/bulk-vault-conversion-desc", "--location", "target/v1-cs-more.store"};
        try {
            executeCommandAndCheckStatus(args);
        } catch (Exception e) {
            Assert.assertTrue(e.getCause().getMessage().indexOf("ELYTOOL00013") > -1
                && e.getCause().getMessage().indexOf("location") > -1);
        }
    }

}
