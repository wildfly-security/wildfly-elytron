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

import static org.wildfly.security.keystore.ElytronMessages.log;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.concurrent.atomic.AtomicReference;

/**
 * The {@link KeyStoreSpi} to add support atomic loading of the {@link KeyStore}
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class AtomicLoadKeyStoreSpi extends DelegatingKeyStoreSpi {

    private final KeyStoreFactory keyStoreFactory;

    private final AtomicReference<KeyStore> currentStore = new AtomicReference<KeyStore>();

    AtomicLoadKeyStoreSpi(KeyStoreFactory keyStoreFactory) {
        this.keyStoreFactory = keyStoreFactory;
    }

    @Override
    public void engineLoad(InputStream stream, char[] password) throws IOException, NoSuchAlgorithmException, CertificateException {

        ElytronMessages.tls.tracef("AtomicLoadKeyStore loading:  stream = %s,  password = %b", stream, password != null);
        try {
            KeyStore keyStore = keyStoreFactory.getInstance();
            keyStore.load(stream, password);
            currentStore.set(keyStore);
        } catch (KeyStoreException e) {
            throw log.unableToCreateKeyStore(e);
        }
    }

    KeyStore getCurrentKeyStore() {
        return currentStore.get();
    }

    void restoreKeyStore(final KeyStore keyStore) {
        currentStore.set(keyStore);
    }

    @Override
    protected KeyStore getKeyStore() {
        return currentStore.get();
    }

}
