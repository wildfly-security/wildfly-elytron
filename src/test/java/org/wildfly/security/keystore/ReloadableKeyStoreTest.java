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

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStore.ProtectionParameter;
import java.security.cert.X509Certificate;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.wildfly.security.keystore.KeyStoreWatcher.Store;

import sun.security.x509.CertAndKeyGen;
import sun.security.x509.X500Name;

/**
 * Test case to test support for reloadable key stores.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class ReloadableKeyStoreTest {

    private static final String KEY_STORE_TYPE = "jks";
    private static final char[] STORE_PASSWORD = "password".toCharArray();
    private static final String DEFAULT_ALIAS = "default";
    private static final String TEST_ALAIS = "test";

    private File workingDir = null;
    private File tempFile = null;
    private File keystoreFile = null;

    /**
     * This is the working key store being used to modify the contents of the store, the store being tested is created in the
     * individual tests.
     */
    private KeyStore workingKeyStore = null;

    @Before
    public void beforeTest() throws GeneralSecurityException, IOException {
        workingDir = getWorkingDir();
        tempFile = new File(workingDir, "temp.jks");
        keystoreFile = new File(workingDir, "keystore.jks");

        workingKeyStore = emptyKeyStore();
        addKeyPairAndCert(DEFAULT_ALIAS);
        save();
    }

    @After
    public void afterTest() {
        keystoreFile.delete();
        keystoreFile = null;
        workingDir.delete();
        workingDir = null;
    }

    @Test
    public void verifyStoreUpdates() throws Exception {
        try (ReloadableFileKeyStore testedStore = reloadableKeyStore()) {
            StoreCountDown countDown = new StoreCountDown();
            KeyStoreWatcher.getDefault().register(keystoreFile, countDown);

            assertTrue(testedStore.containsAlias(DEFAULT_ALIAS));
            assertFalse(testedStore.containsAlias(TEST_ALAIS));

            addKeyPairAndCert(TEST_ALAIS);
            save();

            countDown.await();
            assertTrue(testedStore.containsAlias(DEFAULT_ALIAS));
            assertTrue(testedStore.containsAlias(TEST_ALAIS));

            remove(DEFAULT_ALIAS);
            countDown.reset();
            save();

            countDown.await();
            assertFalse(testedStore.containsAlias(DEFAULT_ALIAS));
            assertTrue(testedStore.containsAlias(TEST_ALAIS));

            KeyStoreWatcher.getDefault().deRegister(keystoreFile, countDown);
        }
    }

    private ReloadableFileKeyStore reloadableKeyStore() throws GeneralSecurityException, IOException {
        ReloadableFileKeyStore theStore  = ReloadableFileKeyStore.getInstance(KEY_STORE_TYPE, keystoreFile, STORE_PASSWORD);
        theStore.load(null, null);

        return theStore;
    }

    private KeyStore emptyKeyStore() throws GeneralSecurityException, IOException {
        KeyStore theStore = KeyStore.getInstance(KEY_STORE_TYPE);
        theStore.load(null, null);

        return theStore;
    }

    @SuppressWarnings("restriction")
    private void addKeyPairAndCert(final String alias) throws GeneralSecurityException, IOException {
        CertAndKeyGen keyGen = new CertAndKeyGen("RSA", "SHA1WithRSA");
        keyGen.generate(512); // For the purpose of this test, as small as we can go.
        X509Certificate cert = keyGen.getSelfCertificate(new X500Name(String.format("cn=%s", alias)), 31536000); // Validity one
                                                                                                                 // year.

        ProtectionParameter pp = new KeyStore.PasswordProtection(STORE_PASSWORD);
        PrivateKeyEntry pke = new PrivateKeyEntry(keyGen.getPrivateKey(), new X509Certificate[] { cert });

        workingKeyStore.setEntry(alias, pke, pp);
    }

    private void remove(final String alias) throws GeneralSecurityException{
        workingKeyStore.deleteEntry(alias);
    }

    private void save() throws IOException, GeneralSecurityException {
        try (FileOutputStream fos = new FileOutputStream(tempFile)) {
            workingKeyStore.store(fos, STORE_PASSWORD);
        }
        tempFile.renameTo(keystoreFile);
    }

    private static File getWorkingDir() {
        File workingDir = new File("./target/keystore");
        if (workingDir.exists() == false) {
            workingDir.mkdirs();
        }

        return workingDir;
    }

    private static class StoreCountDown implements Store {

        private volatile CountDownLatch latch = new CountDownLatch(1);

        @Override
        public void modified() {
            latch.countDown();
        }

        void reset() {
            latch = new CountDownLatch(1);
        }

        void await() {
            try {
                if (latch.await(1, TimeUnit.SECONDS) == false) {
                    throw new IllegalStateException("Latch never reached '0' but timed out.");
                }
            } catch (InterruptedException e) {
                throw new IllegalStateException("Interrupted waiting for count down.", e);
            }
        }

    }

}
