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
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

/**
 * The {@link KeyStoreSpi} implementation to track modifications.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class ModifyTrackingKeyStoreSpi extends DelegatingKeyStoreSpi {

    private final KeyStore delegate;
    private volatile boolean initialised = false;
    private volatile boolean modified = false;    ModifyTrackingKeyStoreSpi(KeyStore delegate) {
        this.delegate = delegate;
    }

    @Override
    public void engineSetKeyEntry(String alias, Key key, char[] password, Certificate[] chain) throws KeyStoreException {
        super.engineSetKeyEntry(alias, key, password, chain);
        modified = true;
    }

    @Override
    public void engineSetKeyEntry(String alias, byte[] key, Certificate[] chain) throws KeyStoreException {
        super.engineSetKeyEntry(alias, key, chain);
        modified = true;
    }

    @Override
    public void engineSetCertificateEntry(String alias, Certificate cert) throws KeyStoreException {
        super.engineSetCertificateEntry(alias, cert);
        modified = true;
    }

    @Override
    public void engineDeleteEntry(String alias) throws KeyStoreException {
        super.engineDeleteEntry(alias);
        modified = true;
    }

    @Override
    public void engineStore(OutputStream stream, char[] password) throws IOException, NoSuchAlgorithmException,
            CertificateException {
        super.engineStore(stream, password);
        modified = false;
    }

    @Override
    public void engineLoad(InputStream stream, char[] password) throws IOException, NoSuchAlgorithmException, CertificateException {
        if (initialised) {
            super.engineLoad(stream, password);
            modified = false;
        } else {
            // Skip the first initialisation as we are deliberately getting initialised flags set.
            initialised = true;
        }
    }

    /**
     * Identify if the KeyStore has been modified through this implementation since the last call to save or load.
     *
     * @return {@code true} if the {@link KeyStore} has been modified, {@code false} otherwise
     */
    boolean isModified() {
        return modified;
    }

    /**
     * Set the modified flag for this {@link KeyStore}.
     *
     * @param modified the new value of the flag
     */
    void setModified(final boolean modified) {
        this.modified = modified;
    }

    @Override
    protected KeyStore getKeyStore() {
        return delegate;
    }

}
