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
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.security.Provider;
import java.security.Security;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;
import org.wildfly.security.WildFlyElytronPasswordProvider;
import org.wildfly.security.auth.server.IdentityCredentials;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.credential.source.CredentialSource;
import org.wildfly.security.credential.store.CredentialStore;
import org.wildfly.security.credential.store.CredentialStore.CredentialSourceProtectionParameter;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactory;
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

    private PasswordCredential storedCredential;

    private CredentialSourceProtectionParameter storeProtection;

    @Parameters(name = "format={0}")
    public static Iterable<Object[]> keystoreFormats() {
        final String vendor = System.getProperty("java.vendor");
        if ("Oracle Corporation".equals(vendor)) {
            return Arrays.asList(new Object[] { "JCEKS" }, new Object[] { "PKCS12" });
        } else {
            // IBM PKCS12 does not allow storing PasswordCredential (and requires singed JAR)
            // HP requires signed JAR
            return Collections.singletonList(new Object[] { "JCEKS" });
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

        storedCredential = new PasswordCredential(secret);
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

        originalStore.store("key", storedCredential, null);

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
}
