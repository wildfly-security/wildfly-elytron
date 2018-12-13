/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016 Red Hat, Inc., and individual contributors
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
import java.security.KeyStore;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.cert.CertificateException;
import java.util.function.Predicate;

import org.wildfly.common.Assert;

/**
 * A {@link KeyStore} implementation that can wrap another key store instance and filter which aliases can actually be returned.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class FilteringKeyStore extends KeyStore {

    private FilteringKeyStore(KeyStoreSpi keyStoreSpi, Provider provider, String type) {
        super(keyStoreSpi, provider, type);
    }

    /**
     * Wrap an existing initialised {@link KeyStore} with an wrapper to filter which aliases can be returned.
     *
     * @param toWrap the {@link KeyStore} to wrap.
     * @return the filtering wrapper around the {@link KeyStore}
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     * @throws IOException
     * @throws IllegalArgumentException if the {@link KeyStore} being wrapped is {@code null}
     */
    public static KeyStore filteringKeyStore(final KeyStore toWrap, final Predicate<String> aliasPredicate) throws NoSuchAlgorithmException, CertificateException,
            IOException {
        Assert.checkNotNullParam("toWrap", toWrap);

        KeyStore keyStore = new FilteringKeyStore(new FilteringKeyStoreSpi(toWrap, aliasPredicate), toWrap.getProvider(), toWrap.getType());
        keyStore.load(null, null);

        return keyStore;
    }

}
