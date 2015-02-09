/*
 * JBoss, Home of Professional Open Source
 * Copyright 2015 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.keystore;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.ProtectionParameter;
import java.security.KeyStore.SecretKeyEntry;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * Test case to test support for the {@link UnmodifiableKeyStore}
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class UnmodifiableKeyStoreTest {

    private static final String KEY_STORE_TYPE = "jceks";
    private static final char[] STORE_PASSWORD = "password".toCharArray();
    private static final String ALIAS = "one";

    private ProtectionParameter protectionParameter = new PasswordProtection(STORE_PASSWORD);
    private File workingDir = null;
    private File keyStore = null;

    @Before
    public void beforeTest() throws GeneralSecurityException, IOException {
        workingDir = getWorkingDir();

        keyStore = new File(workingDir, "store.jceks");

        KeyStore keyStore = emptyKeyStore();
        addSecretKey(ALIAS, keyStore);
        save(keyStore, this.keyStore);
    }

    @After
    public void afterTest() {
        keyStore.delete();
        keyStore = null;
        workingDir.delete();
        workingDir = null;
    }

    @Test
    public void verifyStoreUpdates() throws Exception {
        KeyStore keyStore = load();
        KeyStore unmodifiable = UnmodifiableKeyStore.unmodifiableKeyStore(keyStore);

        assertEquals(1, unmodifiable.size());
        assertTrue(unmodifiable.containsAlias(ALIAS));

        testExpectUnsupportedOperationException(unmodifiable, (KeyStore k) -> k.deleteEntry(ALIAS));
        testExpectUnsupportedOperationException(unmodifiable, (KeyStore k) -> k.setEntry(ALIAS, new SecretKeyEntry(getSecretKey()), protectionParameter));
        testExpectUnsupportedOperationException(unmodifiable, (KeyStore k) -> k.setCertificateEntry(ALIAS, null));
        testExpectUnsupportedOperationException(unmodifiable, (KeyStore k) -> k.load(null, null));

        assertEquals(1, unmodifiable.size());
        assertTrue(unmodifiable.containsAlias(ALIAS));

        keyStore.deleteEntry(ALIAS);

        assertEquals(0, unmodifiable.size());
        assertFalse(unmodifiable.containsAlias(ALIAS));
    }

    interface TestTask {
        void test(KeyStore keyStore) throws Exception;
    }

    private void testExpectUnsupportedOperationException(final KeyStore keyStore, TestTask test) throws Exception {
        try {
            test.test(keyStore);
            fail("Expected Exception Not Thrown");
        } catch (UnsupportedOperationException e) {
        }
    }

    private KeyStore load() throws GeneralSecurityException, IOException {
        KeyStore keyStore = KeyStore.getInstance(KEY_STORE_TYPE);
        try (FileInputStream fis = new FileInputStream(this.keyStore)) {
            keyStore.load(fis, STORE_PASSWORD);
        }
        return keyStore;
    }

    private KeyStore emptyKeyStore() throws GeneralSecurityException, IOException {
        KeyStore theStore = KeyStore.getInstance(KEY_STORE_TYPE);
        theStore.load(null, null);

        return theStore;
    }

    private SecretKey getSecretKey() throws GeneralSecurityException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);

        return keyGen.generateKey();
    }

    private void addSecretKey(final String alias, final KeyStore keyStore) throws GeneralSecurityException {
        SecretKey key = getSecretKey();

        keyStore.setEntry(alias, new SecretKeyEntry(key), protectionParameter);
    }

    private void save(KeyStore keyStore, File target) throws IOException, GeneralSecurityException {
        try (FileOutputStream fos = new FileOutputStream(target)) {
            keyStore.store(fos, STORE_PASSWORD);
        }
    }

    private static File getWorkingDir() {
        File workingDir = new File("./target/keystore");
        if (workingDir.exists() == false) {
            workingDir.mkdirs();
        }

        return workingDir;
    }

}
