/*
 * Copyright 2021 Red Hat, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wildfly.security.tool;

import static org.junit.Assume.assumeTrue;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import javax.crypto.SecretKey;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;
import org.wildfly.security.credential.SecretKeyCredential;
import org.wildfly.security.credential.store.CredentialStore;
import org.wildfly.security.encryption.CipherUtil;
import org.wildfly.security.encryption.SecretKeyUtil;

/**
 * Test case to cover {@code SecretKey} management using the credential-store command.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
@RunWith(Parameterized.class)
public class SecretKeyCommandTest extends AbstractCommandTest {

    private static final String ALIAS = "testkey";
    private static final String PASSWORD = "cspassword";

    private static final String CLEAR_TEXT = "SomeSecretPassword";

    private static final String PASSWORD_ALIAS = "MyPassword";
    private static final String CLEAR_TEXT_WITH_SPACE = "Some Secret Password";

    private static final String KEY_STORE_CS = "KeyStoreCredentialStore";
    private static final String PROPERTIES_CS = "PropertiesCredentialStore";

    @Parameter
    public String credentialStoreType;

    @Parameters
    public static List<String> getTypes() {
        return Arrays.asList(new String[] { KEY_STORE_CS, PROPERTIES_CS });
    }

    @Override
    protected String getCommandType() {
        return CredentialStoreCommand.CREDENTIAL_STORE_COMMAND;
    }

    @Test
    public void testGenerateSecretKey() throws Exception {
        String storageLocation = getStoragePathForNewFile();

        String[] args = getArgs(storageLocation, true, new String[] { "--create", "--generate-secret-key", ALIAS});
        executeCommandAndCheckStatus(args);

        CredentialStore store = getExistingCredentialStore(storageLocation);
        store.exists(ALIAS, SecretKeyCredential.class);
    }

    @Test
    public void testExportSecretKey() throws Exception {
        String storageLocation = getStoragePathForNewFile();

        String[] args = getArgs(storageLocation, true, new String[] { "--create", "--generate-secret-key", ALIAS });
        executeCommandAndCheckStatus(args);

        args = getArgs(storageLocation, false, new String[] { "--export-secret-key", ALIAS });
        String output = executeCommandAndCheckStatusAndGetOutput(args);
        int startPos = output.indexOf(ALIAS) + ALIAS.length() + 1;
        String key = output.substring(startPos, output.length() -1);

        SecretKey secretKey = SecretKeyUtil.importSecretKey(key);

        CredentialStore store = getExistingCredentialStore(storageLocation);
        SecretKeyCredential secretKeyCredential = store.retrieve(ALIAS, SecretKeyCredential.class);

        assertEquals("Matching keys", secretKey, secretKeyCredential.getSecretKey());
    }

    // TODO We also need a test which includes being prompted for the key.
    @Test
    public void testImportSecretKey() throws Exception {
        String storageLocation = getStoragePathForNewFile();

        SecretKey secretKey = SecretKeyUtil.generateSecretKey(128);
        String encoded = SecretKeyUtil.exportSecretKey(secretKey);

        String[] args = getArgs(storageLocation, true, "--create", "--import-secret-key", ALIAS, "--key", encoded);
        executeCommandAndCheckStatus(args);

        CredentialStore store = getExistingCredentialStore(storageLocation);
        SecretKeyCredential secretKeyCredential = store.retrieve(ALIAS, SecretKeyCredential.class);

        assertEquals("Matching keys", secretKey, secretKeyCredential.getSecretKey());
    }

    // TODO We also need a test which includes being prompted for the clear text.
    @Test
    public void testEncryptClearText() throws Exception {
        String storageLocation = getStoragePathForNewFile();

        String[] args = getArgs(storageLocation, true, new String[] { "--create", "--generate-secret-key", ALIAS });
        executeCommandAndCheckStatus(args);

        args = getArgs(storageLocation, false, new String[] { "--encrypt", ALIAS, "--clear-text", CLEAR_TEXT});
        String output = executeCommandAndCheckStatusAndGetOutput(args);
        int start = output.indexOf('\'');
        int end = output.indexOf('\'', start + 1);
        String token = output.substring(start + 1, end);

        CredentialStore store = getExistingCredentialStore(storageLocation);
        SecretKeyCredential secretKeyCredential = store.retrieve(ALIAS, SecretKeyCredential.class);

        String decrypted = CipherUtil.decrypt(token, secretKeyCredential.getSecretKey());
        assertEquals("Expected original clear text", CLEAR_TEXT, decrypted);
    }

    @Test
    public void testEncryptClearTextEntry() throws Exception {
        // This test can only run on a credential store that supports PasswordCredential storage.
        assumeTrue(KEY_STORE_CS.equals(credentialStoreType));

        String storageLocation = getStoragePathForNewFile();

        String[] args = getArgs(storageLocation, true, "--create", "--generate-secret-key", ALIAS);
        executeCommandAndCheckStatus(args);

        args = getArgs(storageLocation, true, "--add", PASSWORD_ALIAS, "--secret", CLEAR_TEXT_WITH_SPACE);
        executeCommandAndCheckStatus(args);

        args = getArgs(storageLocation, false, "--encrypt", ALIAS, "--entry", PASSWORD_ALIAS);
        String output = executeCommandAndCheckStatusAndGetOutput(args);
        int start = output.indexOf('\'');
        int end = output.indexOf('\'', start + 1);
        String token = output.substring(start + 1, end);

        CredentialStore store = getExistingCredentialStore(storageLocation);
        SecretKeyCredential secretKeyCredential = store.retrieve(ALIAS, SecretKeyCredential.class);

        String decrypted = CipherUtil.decrypt(token, secretKeyCredential.getSecretKey());
        assertEquals("Expected original clear text", CLEAR_TEXT_WITH_SPACE, decrypted);
    }

    @Test
    public void testQueryActions() throws Exception {
        String storageLocation = getStoragePathForNewFile();

        String[] args = getArgs(storageLocation, true, new String[] { "--create", "--generate-secret-key", ALIAS });
        executeCommandAndCheckStatus(args);

        args = getArgs(storageLocation, false, new String[] { "--aliases" });
        String output = executeCommandAndCheckStatusAndGetOutput(args);
        assertTrue("Expected alias listed", output.contains(ALIAS));

        args = getArgs(storageLocation, false, new String[] { "--exists", ALIAS, "--entry-type", "SecretKeyCredential" });
        output = executeCommandAndCheckStatusAndGetOutput(args);
        assertEquals("Expected Output", "Alias \"testkey\" exists", output.trim());

        if (PROPERTIES_CS.equals(credentialStoreType)) {
            args = getArgs(storageLocation, false, new String[] { "--exists", ALIAS});
            output = executeCommandAndCheckStatusAndGetOutput(args);
            assertEquals("Expected Output", "Alias \"testkey\" exists", output.trim());
        }

        args = getArgs(storageLocation, false, new String[] { "--remove", ALIAS, "--entry-type", "SecretKeyCredential" });
        output = executeCommandAndCheckStatusAndGetOutput(args);
        assertEquals("Alias \"testkey\" of type \"SecretKeyCredential\" has been successfully removed", output.trim());

        if (PROPERTIES_CS.equals(credentialStoreType)) {
            args = getArgs(storageLocation, false, new String[] { "--create", "--generate-secret-key", ALIAS });
            executeCommandAndCheckStatus(args);

            args = getArgs(storageLocation, false, new String[] { "--remove", ALIAS });
            output = executeCommandAndCheckStatusAndGetOutput(args);
            assertEquals("Alias \"testkey\" has been successfully removed", output.trim());
        }

        args = getArgs(storageLocation, false, new String[] { "--aliases" });
        output = executeCommandAndCheckStatusAndGetOutput(args);
        assertFalse("Expected alias listed", output.contains(ALIAS));

        args = getArgs(storageLocation, false, new String[] { "--exists", ALIAS, "--entry-type", "SecretKeyCredential" });
        output = executeCommandAndCheckStatusAndGetOutput(args, CredentialStoreCommand.ALIAS_NOT_FOUND);
        assertEquals("Expected Output", "Alias \"testkey\" of type \"SecretKeyCredential\" does not exist", output.trim());

        if (PROPERTIES_CS.equals(credentialStoreType)) {
            args = getArgs(storageLocation, false, new String[] { "--exists", ALIAS});
            output = executeCommandAndCheckStatusAndGetOutput(args, CredentialStoreCommand.ALIAS_NOT_FOUND);
            assertEquals("Expected Output", "Alias \"testkey\" does not exist", output.trim());
        }
    }

    private CredentialStore getExistingCredentialStore(final String storageLocation) throws Exception {
        if (KEY_STORE_CS.equals(credentialStoreType)) {
            return getCredentialStoreStorageFromExistsFile(storageLocation, PASSWORD);
        } else if (PROPERTIES_CS.equals(credentialStoreType)) {
            CredentialStore credentialStore = CredentialStore.getInstance(PROPERTIES_CS);
            credentialStore.initialize(Collections.singletonMap("location", storageLocation));

            return credentialStore;
        }

        throw new IllegalStateException();
    }

    private String[] getArgs(String storageLocation, boolean summary, String... additionalArgs) {
        ArrayList<String> arguments = new ArrayList<>();
        arguments.add("--location=" + storageLocation);
        for (String additional : additionalArgs) {
            arguments.add(additional);
        }

        if (summary) {
            arguments.add("--summary");
        }
        if (KEY_STORE_CS.equals(credentialStoreType)) {
            arguments.add("--password");
            arguments.add(PASSWORD);
        } else if (PROPERTIES_CS.equals(credentialStoreType)) {
            arguments.add("--type");
            arguments.add(PROPERTIES_CS);
        }

        return arguments.toArray(new String[arguments.size()]);
    }
}
