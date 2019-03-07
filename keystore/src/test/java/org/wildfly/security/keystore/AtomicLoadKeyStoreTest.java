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
import org.wildfly.security.keystore.AtomicLoadKeyStore.LoadKey;

/**
 * Test case to test support for the {@link AtomicLoadKeyStore}
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class AtomicLoadKeyStoreTest {

    private static final String KEY_STORE_TYPE = "jceks";
    private static final char[] STORE_PASSWORD = "password".toCharArray();
    private static final String ALIAS_ONE = "one";
    private static final String ALIAS_TWO = "two";

    private ProtectionParameter protectionParameter = new PasswordProtection(STORE_PASSWORD);
    private File workingDir = null;
    private File keyStoreOne = null;
    private File keyStoreTwo = null;

    @Before
    public void beforeTest() throws GeneralSecurityException, IOException {
        workingDir = getWorkingDir();

        keyStoreOne = new File(workingDir, "storeOne.jceks");
        keyStoreTwo = new File(workingDir, "storeTwo.jceks");

        KeyStore keyStoreOne = emptyKeyStore();
        addSecretKey(ALIAS_ONE, keyStoreOne);
        save(keyStoreOne, this.keyStoreOne);

        KeyStore keyStoreTwo = emptyKeyStore();
        addSecretKey(ALIAS_TWO, keyStoreTwo);
        save(keyStoreTwo, this.keyStoreTwo);
    }

    @After
    public void afterTest() {
        keyStoreOne.delete();
        keyStoreOne = null;
        keyStoreTwo.delete();
        keyStoreTwo = null;
        workingDir.delete();
        workingDir = null;
    }

    @Test
    public void verifyStoreUpdates() throws Exception {
        AtomicLoadKeyStore theStore = atomicLoadKeyStore();

        assertEquals("Initial store should be empty", 0, theStore.size());

        load(theStore, keyStoreOne);

        assertTrue(theStore.containsAlias(ALIAS_ONE));
        assertFalse(theStore.containsAlias(ALIAS_TWO));

        LoadKey key = load(theStore, keyStoreTwo);

        assertFalse(theStore.containsAlias(ALIAS_ONE));
        assertTrue(theStore.containsAlias(ALIAS_TWO));

        theStore.revert(key);

        assertTrue(theStore.containsAlias(ALIAS_ONE));
        assertFalse(theStore.containsAlias(ALIAS_TWO));
    }

    @Test
    public void testAtomize() throws Exception {
        KeyStore keyStoreOne = KeyStore.getInstance(KEY_STORE_TYPE);
        keyStoreOne.load(new FileInputStream(this.keyStoreOne), STORE_PASSWORD);

        AtomicLoadKeyStore theStore = AtomicLoadKeyStore.atomize(keyStoreOne);

        assertTrue(theStore.containsAlias(ALIAS_ONE));
        assertFalse(theStore.containsAlias(ALIAS_TWO));

        LoadKey key = load(theStore, keyStoreTwo);

        assertFalse(theStore.containsAlias(ALIAS_ONE));
        assertTrue(theStore.containsAlias(ALIAS_TWO));

        theStore.revert(key);

        assertTrue(theStore.containsAlias(ALIAS_ONE));
        assertFalse(theStore.containsAlias(ALIAS_TWO));
    }

    private AtomicLoadKeyStore atomicLoadKeyStore() throws GeneralSecurityException, IOException {
        AtomicLoadKeyStore theStore = AtomicLoadKeyStore.newInstance(KEY_STORE_TYPE);
        theStore.load(null, null);

        return theStore;
    }

    private LoadKey load(AtomicLoadKeyStore keyStore, File source) throws Exception {
        try (FileInputStream fis = new FileInputStream(source)) {
            return keyStore.revertibleLoad(fis, STORE_PASSWORD);
        }
    }

    private KeyStore emptyKeyStore() throws GeneralSecurityException, IOException {
        KeyStore theStore = KeyStore.getInstance(KEY_STORE_TYPE);
        theStore.load(null, null);

        return theStore;
    }

    private void addSecretKey(final String alias, final KeyStore keyStore) throws GeneralSecurityException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        SecretKey key = keyGen.generateKey();

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
