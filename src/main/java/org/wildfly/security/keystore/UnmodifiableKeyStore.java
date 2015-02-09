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
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.cert.CertificateException;

/**
 * A wrapper around {@link KeyStore} to make it unmodifiable.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class UnmodifiableKeyStore extends KeyStore {

    private UnmodifiableKeyStore(KeyStoreSpi keyStoreSpi, Provider provider, String type) {
        super(keyStoreSpi, provider, type);
    }

    /**
     * Wrap an existing initialised {@link KeyStore} with an unmodifiable wrapper.
     *
     * Note: References are held to the underlying {@link KeyStore} can still be modified and changes will still be visible in
     * the representation returned here.
     *
     * @param toWrap the {@link KeyStore} to wrap.
     * @return the unmodifiable wrapper around the {@link KeyStore}
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     * @throws IOException
     * @throws IllegalArgumentException if the {@link KeyStore} being wrapped is {@code null}
     */
    public static KeyStore unmodifiableKeyStore(final KeyStore toWrap) throws NoSuchAlgorithmException, CertificateException,
            IOException {
        if (toWrap == null) {
            throw log.nullParameter("toWrap");
        }

        KeyStore keyStore = new UnmodifiableKeyStore(new UnmodifiableKeyStoreSpi(toWrap), toWrap.getProvider(),
                toWrap.getType());
        keyStore.load(null, null);

        return keyStore;
    }
}
