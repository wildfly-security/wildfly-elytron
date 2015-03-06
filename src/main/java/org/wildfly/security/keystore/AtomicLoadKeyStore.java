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
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.cert.CertificateException;

/**
 * A {@link KeyStore} wrapper that makes the load operation atomic, in addition it also gives the ability to reverse the load
 * call.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class AtomicLoadKeyStore extends KeyStore {

    private final AtomicLoadKeyStoreSpi keyStoreSpi;

    private AtomicLoadKeyStore(AtomicLoadKeyStoreSpi keyStoreSpi, Provider provider, String type) {
        super(keyStoreSpi, provider, type);
        this.keyStoreSpi = keyStoreSpi;
    }

    /**
     * Create a new {@code AtomicLoadKeyStore} wrapping a {@link KeyStore} of the type specified.
     *
     * @param type the type of {@link KeyStore} to be wrapped.
     * @param provider the provide to use to create the {@link KeyStore}
     * @return the new {@code AtomicLoadKeyStore} instance.
     * @throws KeyStoreException If there is a problem creating the {@link KeyStore}
     * @throws NoSuchProviderException if the provider specified can not be found.
     */
    public static AtomicLoadKeyStore newInstance(final String type, final String provider) throws KeyStoreException, NoSuchProviderException {
        KeyStore keyStore = provider != null ? KeyStore.getInstance(type, provider) : KeyStore.getInstance(type);
        final Provider resolvedProvider = keyStore.getProvider();

        AtomicLoadKeyStoreSpi keyStoreSpi = new AtomicLoadKeyStoreSpi(() -> KeyStore.getInstance(type, resolvedProvider));

        return new AtomicLoadKeyStore(keyStoreSpi, resolvedProvider, type);
    }

    /**
     * Create a new {@code AtomicLoadKeyStore} wrapping a {@link KeyStore} of the type specified.
     *
     * @param type the type of {@link KeyStore} to be wrapped.
     * @return the new {@code AtomicLoadKeyStore} instance.
     * @throws KeyStoreException If there is a problem creating the {@link KeyStore}
     */
    public static AtomicLoadKeyStore newInstance(final String type) throws KeyStoreException {
        try {
            return newInstance(type, null);
        } catch (NoSuchProviderException e) {
            throw new KeyStoreException(e);
        }
    }

    /**
     * Performs the same action as {@link #load(InputStream, char[])} except a {@link LoadKey} is returned that can be used to revert the load.
     *
     * @param inputStream the stream to load from or {@code null}
     * @param password the password used to protect the contents of the {@link KeyStore} or {@code null}
     * @return A {@link LoadKey} that can be used to revert the load and restore the previous {@link KeyStore} state.
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     * @throws IOException
     */
    public LoadKey revertableload(final InputStream inputStream, final char[] password) throws NoSuchAlgorithmException, CertificateException, IOException {
        KeyStore current = keyStoreSpi.getCurrentKeyStore();
        if (current == null) {
            throw log.revertableLoadNotPossible();
        }

        load(inputStream, password);

        return new LoadKey(current);
    }

    public void revert(LoadKey key) {
        keyStoreSpi.restoreKeyStore(key.keyStore);
    }

    public class LoadKey {

        private final KeyStore keyStore;

        private LoadKey(KeyStore keyStore) {
            this.keyStore = keyStore;
        }

    }

}
