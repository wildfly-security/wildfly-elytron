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

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import org.wildfly.security.keystore.KeyStoreWatcher.Store;
import org.wildfly.security.keystore.ReloadableFileKeyStore.KeyStoreObserver;

/**
 * The {@link KeyStoreSpi} to add support for reloading based on modifications.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class ReloadableKeyStoreSpiImpl extends KeyStoreSpi implements Store {

    private final String type;
    private final Provider provider;
    private final File storeLocation;
    private final char[] storePassword;

    private final List<KeyStoreObserver> observers = new ArrayList<KeyStoreObserver>();

    private final AtomicReference<KeyStore> currentStore = new AtomicReference<KeyStore>();

    ReloadableKeyStoreSpiImpl(String type, Provider provider, File storeLocation, char[] storePassword)
            throws KeyStoreException {
        this.type = type;
        this.provider = provider;
        this.storeLocation = storeLocation;
        this.storePassword = storePassword.clone();
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
        if (stream != null || password != null) {
            throw new IllegalStateException("Custom load not supported.");
        }

        boolean registrationRequired = currentStore.get() == null;
        doLoad(false);
        if (registrationRequired) {
            KeyStoreWatcher.getDefault().register(storeLocation, this);
        }
    }

    void addObserver(final KeyStoreObserver oberserver) {
        synchronized(observers) {
            observers.add(oberserver);
        }
    }

    void removeObserver(final KeyStoreObserver oberserver) {
        synchronized(observers) {
            observers.remove(oberserver);
        }
    }

    private void doLoad(boolean dontFail) {
        KeyStore theStore;
        try {
            theStore = provider == null ? KeyStore.getInstance(type) : KeyStore.getInstance(type, provider);
        } catch (KeyStoreException e) {
            throw new IllegalStateException(e);
        }

        try (FileInputStream fis = new FileInputStream(storeLocation)) {
            theStore.load(fis, storePassword);

            currentStore.set(theStore);

            synchronized(observers) {
                for (KeyStoreObserver current : observers) {
                    current.updated();
                }
            }
        } catch (IOException | NoSuchAlgorithmException | CertificateException e) {
            if (dontFail == false) {
                throw new IllegalStateException("Unable to load KeyStore", e);
            }
        }
    }

    @Override
    public void modified() {
        System.out.println("SPI Modified");
        doLoad(true);
    }

    void close() throws IOException {
        KeyStoreWatcher.getDefault().deRegister(storeLocation, this);
    }

}
