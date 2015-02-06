/*
 * JBoss, Home of Professional Open Source.
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

import static org.wildfly.security._private.ElytronMessages.log;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Date;
import java.util.Enumeration;
import java.util.concurrent.atomic.AtomicReference;

/**
 * The {@link KeyStoreSpi} to add support atomic loading of the {@link KeyStore}
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class AtomicLoadKeyStoreSPI extends KeyStoreSpi {

    private final KeyStoreFactory keyStoreFactory;

    private boolean initialised = false;
    private final AtomicReference<KeyStore> currentStore = new AtomicReference<KeyStore>();

    AtomicLoadKeyStoreSPI(KeyStoreFactory keyStoreFactory) throws KeyStoreException, NoSuchProviderException {
        this.keyStoreFactory = keyStoreFactory;
        currentStore.set(keyStoreFactory.getInstance());
    }

    Provider getProvider() {
        return currentStore.get().getProvider();
    }

    @Override
    public Key engineGetKey(String alias, char[] password) throws NoSuchAlgorithmException, UnrecoverableKeyException {
        try {
            return currentStore.get().getKey(alias, password);
        } catch (KeyStoreException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public Certificate[] engineGetCertificateChain(String alias) {
        try {
            return currentStore.get().getCertificateChain(alias);
        } catch (KeyStoreException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public Certificate engineGetCertificate(String alias) {
        try {
            return currentStore.get().getCertificate(alias);
        } catch (KeyStoreException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public Date engineGetCreationDate(String alias) {
        try {
            return currentStore.get().getCreationDate(alias);
        } catch (KeyStoreException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public void engineSetKeyEntry(String alias, Key key, char[] password, Certificate[] chain) throws KeyStoreException {
        currentStore.get().setKeyEntry(alias, key, password, chain);
    }

    @Override
    public void engineSetKeyEntry(String alias, byte[] key, Certificate[] chain) throws KeyStoreException {
        currentStore.get().setKeyEntry(alias, key, chain);
    }

    @Override
    public void engineSetCertificateEntry(String alias, Certificate cert) throws KeyStoreException {
        currentStore.get().setCertificateEntry(alias, cert);
    }

    @Override
    public void engineDeleteEntry(String alias) throws KeyStoreException {
        currentStore.get().deleteEntry(alias);
    }

    @Override
    public Enumeration<String> engineAliases() {
        try {
            return currentStore.get().aliases();
        } catch (KeyStoreException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public boolean engineContainsAlias(String alias) {
        try {
            return currentStore.get().containsAlias(alias);
        } catch (KeyStoreException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public int engineSize() {
        try {
            return currentStore.get().size();
        } catch (KeyStoreException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public boolean engineIsKeyEntry(String alias) {
        try {
            return currentStore.get().isKeyEntry(alias);
        } catch (KeyStoreException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public boolean engineIsCertificateEntry(String alias) {
        try {
            return currentStore.get().isCertificateEntry(alias);
        } catch (KeyStoreException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public String engineGetCertificateAlias(Certificate cert) {
        try {
            return currentStore.get().getCertificateAlias(cert);
        } catch (KeyStoreException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public void engineStore(OutputStream stream, char[] password) throws IOException, NoSuchAlgorithmException,
            CertificateException {
        try {
            currentStore.get().store(stream, password);
        } catch (KeyStoreException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public void engineLoad(InputStream stream, char[] password) throws IOException, NoSuchAlgorithmException,
            CertificateException {
        try {
            KeyStore keyStore = initialised ? keyStoreFactory.getInstance() : currentStore.get();
            keyStore.load(stream, password);
            if (initialised) {
                currentStore.set(keyStore);
            }
            initialised = true;
        } catch (NoSuchProviderException | KeyStoreException e) {
            throw log.unableToCreateKeyStore(e);
        }
    }

    boolean isInitialised() {
        return initialised;
    }

    KeyStore getCurrentKeyStore() {
        return currentStore.get();
    }

    void restoreKeyStore(final KeyStore keyStore) {
        currentStore.set(keyStore);
    }

}
