/*
 * JBoss, Home of Professional Open Source.
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

package org.wildfly.security.credential.store.impl;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Provider;
import java.security.Security;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;
import org.wildfly.security.auth.server.IdentityCredentials;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.credential.SecretKeyCredential;
import org.wildfly.security.credential.source.CredentialSource;
import org.wildfly.security.credential.store.CredentialStore;
import org.wildfly.security.credential.store.CredentialStore.CredentialSourceProtectionParameter;
import org.wildfly.security.encryption.SecretKeyUtil;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.WildFlyElytronPasswordProvider;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;

@RunWith(Parameterized.class)
public class KeyStoreCredentialStoreTest {

    @Parameter
    public String keyStoreFormat;

    @Rule
    public TemporaryFolder tmp = new TemporaryFolder();

    private final char[] keyStorePassword = "The quick brown fox jumped over the lazy dog".toCharArray();

    private PasswordFactory passwordFactory;

    private String providerName;

    private char[] secretPassword;

    private PasswordCredential storedPasswordCredential;
    private SecretKeyCredential storedSecretKeyCredential;

    private CredentialSourceProtectionParameter storeProtection;

    @Parameters(name = "format={0}")
    public static Iterable<Object[]> keystoreFormats() {
        final String vendor = System.getProperty("java.vendor");
        if (vendor.contains("IBM") || vendor.toLowerCase().contains("hewlett")) {
            // IBM PKCS12 does not allow storing PasswordCredential (and requires singed JAR)
            // HP requires signed JAR
            return Collections.singletonList(new Object[] { "JCEKS" });
        } else {
            return Arrays.asList(new Object[] { "JCEKS" }, new Object[] { "PKCS12" });
        }
    }

    @Before
    public void installWildFlyElytronProvider() throws Exception {
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

    @Test
    public void shouldSupportKeyStoreFormat() throws Exception {
        final KeyStoreCredentialStore originalStore = new KeyStoreCredentialStore();

        final File keyStoreFile = new File(tmp.getRoot(), "keystore");

        final Map<String, String> attributes = new HashMap<>();
        attributes.put("location", keyStoreFile.getAbsolutePath());
        attributes.put("create", Boolean.TRUE.toString());
        attributes.put("keyStoreType", keyStoreFormat);

        originalStore.initialize(attributes, storeProtection, null);

        originalStore.store("key", storedPasswordCredential, null);

        originalStore.flush();

        assertTrue(keyStoreFile.exists());

        final KeyStoreCredentialStore retrievalStore = new KeyStoreCredentialStore();
        attributes.put("modifiable", "false");

        retrievalStore.initialize(attributes, storeProtection, null);

        final PasswordCredential retrievedCredential = retrievalStore.retrieve("key", PasswordCredential.class, null,
                null, null);

        final ClearPasswordSpec retrievedPassword = passwordFactory.getKeySpec(retrievedCredential.getPassword(),
                ClearPasswordSpec.class);

        assertArrayEquals(secretPassword, retrievedPassword.getEncodedPassword());
    }

    @Test
    public void multipleCredentialTypes() throws Exception {
        final KeyStoreCredentialStore originalStore = new KeyStoreCredentialStore();

        final File keyStoreFile = new File(tmp.getRoot(), "keystore");

        final Map<String, String> attributes = new HashMap<>();
        attributes.put("location", keyStoreFile.getAbsolutePath());
        attributes.put("create", Boolean.TRUE.toString());
        attributes.put("keyStoreType", keyStoreFormat);

        originalStore.initialize(attributes, storeProtection, null);

        originalStore.store("key", storedPasswordCredential, null);
        originalStore.store("key", storedSecretKeyCredential, null);

        originalStore.flush();

        assertTrue(keyStoreFile.exists());

        final KeyStoreCredentialStore retrievalStore = new KeyStoreCredentialStore();
        retrievalStore.initialize(attributes, storeProtection, null);

        Set<String> aliases = retrievalStore.getAliases();
        assertEquals("Expected alias count", 1, aliases.size());
        assertTrue("Expected alias 'key'", aliases.contains("key"));

        final PasswordCredential retrievedPasswordCredential = retrievalStore.retrieve("key", PasswordCredential.class, null,
                null, null);

        final ClearPasswordSpec retrievedPassword = passwordFactory.getKeySpec(retrievedPasswordCredential.getPassword(),
                ClearPasswordSpec.class);

        assertArrayEquals(secretPassword, retrievedPassword.getEncodedPassword());

        SecretKeyCredential retrievedSecretKeyCredential = retrievalStore.retrieve("key", SecretKeyCredential.class, null, null, null);
        assertEquals("Expect SecretKeys to match", storedSecretKeyCredential.getSecretKey(), retrievedSecretKeyCredential.getSecretKey());

        retrievalStore.remove("key", PasswordCredential.class, null, null);

        aliases = retrievalStore.getAliases();
        assertEquals("Expected alias count", 1, aliases.size());
        assertTrue("Expected alias 'key'", aliases.contains("key"));

        retrievalStore.remove("key", SecretKeyCredential.class, null, null);

        aliases = retrievalStore.getAliases();
        assertEquals("Expected alias count", 0, aliases.size());
    }

    @Test
    public void symbolicLinkLocation() throws Exception {
        final KeyStoreCredentialStore originalStore = new KeyStoreCredentialStore();

        final File keyStoreFile = new File(tmp.getRoot(), "keystore");

        final Map<String, String> attributes = new HashMap<>();
        attributes.put("location", keyStoreFile.getAbsolutePath());
        attributes.put("create", Boolean.TRUE.toString());
        attributes.put("keyStoreType", "JCEKS");

        originalStore.initialize(attributes, storeProtection, null);
        originalStore.store("key", storedPasswordCredential, null);
        originalStore.flush();

        assertTrue(keyStoreFile.exists());

        final KeyStoreCredentialStore retrievalStore = new KeyStoreCredentialStore();

        final File symbolicLinkFile = new File(tmp.getRoot(), "link");
        Files.createSymbolicLink(Paths.get(symbolicLinkFile.getAbsolutePath()), Paths.get(keyStoreFile.getAbsolutePath()));

        final Map<String, String> attributesRetrieval = new HashMap<>();
        attributesRetrieval.put("location", symbolicLinkFile.getAbsolutePath());
        attributesRetrieval.put("keyStoreType", "JCEKS");

        retrievalStore.initialize(attributesRetrieval, storeProtection, null);
        retrievalStore.store("key2", storedPasswordCredential, null);
        retrievalStore.flush();

        assertTrue(Files.isSymbolicLink(Paths.get(symbolicLinkFile.getAbsolutePath())));
    }
}
