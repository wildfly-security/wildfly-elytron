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

import static org.junit.Assert.assertEquals;

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
import org.wildfly.security.encryption.SecretKeyUtil;

/**
 * Test case to cover {@code SecretKey} management using the credential-store command.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
@RunWith(Parameterized.class)
public class SecretKeyCommandTest extends AbstractCommandTest {

    private static final String ALIAS = "testKey";
    private static final String PASSWORD = "cspassword";

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

        // TODO - PropertiesKeyStore does not need a password so the tool should not prompt.
        arguments.add("--password");
        arguments.add(PASSWORD);

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
