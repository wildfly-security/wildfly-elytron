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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Date;
import java.util.Enumeration;

/**
 * A wrapper {@link KeyStoreSpi} implementation around a {@link KeyStore} to make it unmodifiable.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class UnmodifiableKeyStoreSpi extends KeyStoreSpi {

    private final KeyStore keyStore;
    private boolean loaded = false;

    UnmodifiableKeyStoreSpi(KeyStore keyStore) {
        this.keyStore = keyStore;
    }

    @Override
    public Key engineGetKey(String alias, char[] password) throws NoSuchAlgorithmException, UnrecoverableKeyException {
        try {
            return keyStore.getKey(alias, password);
        } catch (KeyStoreException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public Certificate[] engineGetCertificateChain(String alias) {
        try {
            return keyStore.getCertificateChain(alias);
        } catch (KeyStoreException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public Certificate engineGetCertificate(String alias) {
        try {
            return keyStore.getCertificate(alias);
        } catch (KeyStoreException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public Date engineGetCreationDate(String alias) {
        try {
            return keyStore.getCreationDate(alias);
        } catch (KeyStoreException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public void engineSetKeyEntry(String alias, Key key, char[] password, Certificate[] chain) throws KeyStoreException {
        throw new UnsupportedOperationException();
    }

    @Override
    public void engineSetKeyEntry(String alias, byte[] key, Certificate[] chain) throws KeyStoreException {
        throw new UnsupportedOperationException();
    }

    @Override
    public void engineSetCertificateEntry(String alias, Certificate cert) throws KeyStoreException {
        throw new UnsupportedOperationException();
    }

    @Override
    public void engineDeleteEntry(String alias) throws KeyStoreException {
        throw new UnsupportedOperationException();
    }

    @Override
    public Enumeration<String> engineAliases() {
        try {
            return keyStore.aliases();
        } catch (KeyStoreException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public boolean engineContainsAlias(String alias) {
        try {
            return keyStore.containsAlias(alias);
        } catch (KeyStoreException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public int engineSize() {
        try {
            return keyStore.size();
        } catch (KeyStoreException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public boolean engineIsKeyEntry(String alias) {
        try {
            return keyStore.isKeyEntry(alias);
        } catch (KeyStoreException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public boolean engineIsCertificateEntry(String alias) {
        try {
            return keyStore.isCertificateEntry(alias);
        } catch (KeyStoreException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public String engineGetCertificateAlias(Certificate cert) {
        try {
            return keyStore.getCertificateAlias(cert);
        } catch (KeyStoreException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public void engineStore(OutputStream stream, char[] password) throws IOException, NoSuchAlgorithmException,
            CertificateException {
        try {
            keyStore.store(stream, password);
        } catch (KeyStoreException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public void engineLoad(InputStream stream, char[] password) throws IOException, NoSuchAlgorithmException,
            CertificateException {
        if (loaded) {
            throw new UnsupportedOperationException();
        }
        loaded = true;
    }

}
