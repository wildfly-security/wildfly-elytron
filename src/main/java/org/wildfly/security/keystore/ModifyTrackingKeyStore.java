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
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.cert.CertificateException;

/**
 * A {@link KeyStore} implementation that tracks if it's contents have been modified through the API since the last load / save.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class ModifyTrackingKeyStore extends KeyStore {

    private final ModifyTrackingKeyStoreSpi keyStoreSpi;

    private ModifyTrackingKeyStore(ModifyTrackingKeyStoreSpi keyStoreSpi, Provider provider, String type) {
        super(keyStoreSpi, provider, type);

        this.keyStoreSpi = keyStoreSpi;
    }

    /**
     * Wrap an existing initialised {@link KeyStore} with a wrapper to track if it is modified.
     *
     * @param toWrap the {@link KeyStore} to wrap
     * @return the wrapper around the {@link KeyStore}
     * @throws NoSuchAlgorithmException if the keystore could not be loaded due to a missing algorithm
     * @throws CertificateException if the keystore could not be loaded due to a certificate problem
     * @throws IOException if the keystore could not be loaded due to an I/O problem
     * @throws IllegalArgumentException if the {@link KeyStore} being wrapped is {@code null}
     */
    public static ModifyTrackingKeyStore modifyTrackingKeyStore(final KeyStore toWrap) throws NoSuchAlgorithmException, CertificateException,
            IOException {
        if (toWrap == null) {
            throw log.nullParameter("toWrap");
        }

        ModifyTrackingKeyStore keyStore = new ModifyTrackingKeyStore(new ModifyTrackingKeyStoreSpi(toWrap), toWrap.getProvider(),
                toWrap.getType());
        keyStore.load(null, null);

        return keyStore;
    }

    /**
     * Identify if the KeyStore has been modified through this implementation since the last call to save or load.
     *
     * @return {@code true} if the {@link KeyStore} has been modified, {@code false} otherwise.
     */
    public boolean isModified() {
        return keyStoreSpi.isModified();
    }

    /**
     * Mark this as being modified, this can be used where the delegate is delibaratly modified outside this wrapper.
     */
    public void setModified(final boolean modified) {
        keyStoreSpi.setModified(modified);
    }

}
