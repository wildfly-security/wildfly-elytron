/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2024 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.credential.store.impl;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.KeyStore.ProtectionParameter;
import java.security.Provider;
import java.security.Security;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.wildfly.security.auth.server.IdentityCredentials;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.credential.SecretKeyCredential;
import org.wildfly.security.credential.source.CredentialSource;
import org.wildfly.security.credential.store.CredentialStore;
import org.wildfly.security.credential.store.CredentialStore.CredentialSourceProtectionParameter;
import org.wildfly.security.credential.store.CredentialStoreSpi;
import org.wildfly.security.encryption.SecretKeyUtil;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.WildFlyElytronPasswordProvider;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;

/**
 * /**
 * Test case to test the {@code KeyStoreCredentialStore} implementation when
 * configured to persist to an external file.
 *
 * When running in this mode a KeyStore is used to obtain a SecretKey instance
 * and the credentials are encrypted using this SecretKey before being written
 * to the external file.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class ExternalKeyStoreCredentialStoreTest {

    private static final String KEY_KEY_STORE_NAME = "secret.pkcs12";
    private static final String SECRET_KEY_ALIAS = "secret";
    private final char[] keyStorePassword = "The quick brown fox jumped over the lazy dog".toCharArray();

    @Rule
    public TemporaryFolder temporaryFolder = new TemporaryFolder();

    private File keyKeyStoreFile;
    private PasswordFactory passwordFactory;
    private String providerName;

    private char[] secretPassword;
    private PasswordCredential storedPasswordCredential;
    private SecretKeyCredential storedSecretKeyCredential;

    private CredentialSourceProtectionParameter storeProtection;

    @Before
    public void prepareTest() throws Exception {
        /*
         * Step 1 - Create a KeyStore containing a SecretKey to be used for encryption.
         */
        byte[] rawKey = new byte[16];  // 16 bytes = 128 bits
        Arrays.fill(rawKey, (byte) 0x00); // This is a test, we don't need a random key.
        SecretKey secretKey = new SecretKeySpec(rawKey, "AES");

        KeyStore keyKeyStore = KeyStore.getInstance("PKCS12");
        ProtectionParameter keyStoreProtection = new KeyStore.PasswordProtection(keyStorePassword);

        keyKeyStore.load(null, keyStorePassword);
        keyKeyStore.setEntry(SECRET_KEY_ALIAS, new KeyStore.SecretKeyEntry(secretKey), keyStoreProtection);

        keyKeyStoreFile = temporaryFolder.newFile(KEY_KEY_STORE_NAME);

        try (FileOutputStream fos = new FileOutputStream(keyKeyStoreFile)) {
           keyKeyStore.store(fos, keyStorePassword);
        }
        /*
         * Step 2 - Create the PasswordFactory and SecretKeyCredential to be stored.
         */
        final Provider provider = WildFlyElytronPasswordProvider.getInstance();

        providerName = provider.getName();

        Security.addProvider(provider);

        passwordFactory = PasswordFactory.getInstance(ClearPassword.ALGORITHM_CLEAR);
        final Password password = passwordFactory.generatePassword(new ClearPasswordSpec(keyStorePassword));
        final Credential credential = new PasswordCredential(password);
        final CredentialSource credentialSource = IdentityCredentials.NONE.withCredential(credential);

        storeProtection = new CredentialStore.CredentialSourceProtectionParameter(credentialSource);

        secretPassword = "this is a password".toCharArray();

        final Password secret = passwordFactory.generatePassword(new ClearPasswordSpec(secretPassword));

        storedPasswordCredential = new PasswordCredential(secret);
        storedSecretKeyCredential = new SecretKeyCredential(SecretKeyUtil.generateSecretKey(256));
    }

    @After
    public void removeWildFlyElytronProvider() {
        Security.removeProvider(providerName);
    }

    private CredentialStoreSpi getCredentialStore(final File location) throws Exception {
        final KeyStoreCredentialStore keyStoreCredentialStore = new KeyStoreCredentialStore();

        final Map<String, String> attributes = new HashMap<>();
        attributes.put("keyStoreType", "PKCS12");
        attributes.put("keyAlias", SECRET_KEY_ALIAS);
        attributes.put("create", Boolean.TRUE.toString());
        attributes.put("location", keyKeyStoreFile.getAbsolutePath());
        attributes.put("external", Boolean.TRUE.toString());
        attributes.put("externalPath", location.getAbsolutePath());

        keyStoreCredentialStore.initialize(attributes, storeProtection, null);

        return keyStoreCredentialStore;
    }

    @Test
    public void testPasswordCredential() throws Exception {
        final File credentialStoreFile = new File(temporaryFolder.getRoot(), "test.credential.store");

        CredentialStoreSpi credentialStore = getCredentialStore(credentialStoreFile);

        credentialStore.store("testAlias", storedPasswordCredential, null);
        credentialStore.flush();

        assertTrue("Credential Store File Created", credentialStoreFile.exists());

        credentialStore = getCredentialStore(credentialStoreFile);

        final PasswordCredential retrievedCredential = credentialStore.retrieve("testAlias", PasswordCredential.class, null,
                null, null);

        final ClearPasswordSpec retrievedPassword = passwordFactory.getKeySpec(retrievedCredential.getPassword(),
                ClearPasswordSpec.class);

        assertArrayEquals(secretPassword, retrievedPassword.getEncodedPassword());
    }

    @Test
    public void testSecretKeyCredential() throws Exception {
        final File credentialStoreFile = new File(temporaryFolder.getRoot(), "test.credential.store");

        CredentialStoreSpi credentialStore = getCredentialStore(credentialStoreFile);

        credentialStore.store("testAlias", storedSecretKeyCredential, null);
        credentialStore.flush();

        assertTrue("Credential Store File Created", credentialStoreFile.exists());

        credentialStore = getCredentialStore(credentialStoreFile);

        final SecretKeyCredential retrievedSecretKeyCredential = credentialStore.retrieve("testAlias",SecretKeyCredential.class, null,
                null, null);
        assertEquals("Expect SecretKeys to match", storedSecretKeyCredential.getSecretKey(), retrievedSecretKeyCredential.getSecretKey());
    }

    @Test
    public void testBothCredentials() throws Exception {
        final File credentialStoreFile = new File(temporaryFolder.getRoot(), "test.credential.store");

        CredentialStoreSpi credentialStore = getCredentialStore(credentialStoreFile);

        credentialStore.store("testAlias", storedPasswordCredential, null);
        credentialStore.store("testAlias", storedSecretKeyCredential, null);
        credentialStore.flush();

        assertTrue("Credential Store File Created", credentialStoreFile.exists());

        credentialStore = getCredentialStore(credentialStoreFile);

        Set<String> aliases = credentialStore.getAliases();
        assertEquals("Expected alias count", 1, aliases.size());
        assertTrue("Expected alias 'testAlias'", aliases.contains("testalias"));

        final PasswordCredential retrievedCredential = credentialStore.retrieve("testAlias", PasswordCredential.class, null,
                null, null);

        final ClearPasswordSpec retrievedPassword = passwordFactory.getKeySpec(retrievedCredential.getPassword(),
                ClearPasswordSpec.class);
        assertArrayEquals(secretPassword, retrievedPassword.getEncodedPassword());

        final SecretKeyCredential retrievedSecretKeyCredential = credentialStore.retrieve("testAlias",SecretKeyCredential.class, null,
                null, null);
        assertEquals("Expect SecretKeys to match", storedSecretKeyCredential.getSecretKey(), retrievedSecretKeyCredential.getSecretKey());
    }
}
