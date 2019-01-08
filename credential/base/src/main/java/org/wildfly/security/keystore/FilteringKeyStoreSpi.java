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

import org.wildfly.security.credential._private.ElytronMessages;

import java.io.IOException;
import java.io.InputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * A delegating key store implementation that allows for a predicate to be supplied to filter which aliases will actually be
 * returned.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class FilteringKeyStoreSpi extends DelegatingKeyStoreSpi {

    private final KeyStore keyStore;
    private final Predicate<String> aliasPredicate;
    private boolean loaded = false;

    FilteringKeyStoreSpi(final KeyStore keyStore, final Predicate<String> aliasPredicate) {
        this.keyStore = keyStore;
        this.aliasPredicate = aliasPredicate;
        ElytronMessages.tls.tracef("FilteringKeyStore initialization:  keyStore = %s,  aliasPredicate = %s", keyStore, aliasPredicate);
    }

    @Override
    public Key engineGetKey(String alias, char[] password) throws NoSuchAlgorithmException, UnrecoverableKeyException {
        return aliasPredicate.test(alias) ? super.engineGetKey(alias, password) : null;
    }

    @Override
    public Certificate[] engineGetCertificateChain(String alias) {
        return aliasPredicate.test(alias) ? super.engineGetCertificateChain(alias) : null;
    }

    @Override
    public Certificate engineGetCertificate(String alias) {
        return aliasPredicate.test(alias) ? super.engineGetCertificate(alias) : null;
    }

    @Override
    public Date engineGetCreationDate(String alias) {
        return aliasPredicate.test(alias) ? super.engineGetCreationDate(alias) : null;
    }

    @Override
    public boolean engineContainsAlias(String alias) {
        return aliasPredicate.test(alias) ? super.engineContainsAlias(alias) : false;
    }

    @Override
    public boolean engineIsKeyEntry(String alias) {
        return aliasPredicate.test(alias) ? super.engineIsKeyEntry(alias) : false;
    }

    @Override
    public boolean engineIsCertificateEntry(String alias) {
        return aliasPredicate.test(alias) ? super.engineIsCertificateEntry(alias) : false;
    }

    @Override
    public String engineGetCertificateAlias(Certificate cert) {
        String alias = super.engineGetCertificateAlias(cert);
        return alias != null ? aliasPredicate.test(alias) ? alias : null : null;
    }

    private Stream<String> aliasStream() {
       return Collections.list(super.engineAliases()).stream().filter(aliasPredicate);
    }

    @Override
    public Enumeration<String> engineAliases() {
        return Collections.enumeration(aliasStream().collect(Collectors.toList()));
    }

    @Override
    public int engineSize() {
        return aliasStream().mapToInt((String s) -> 1).sum();
    }

    @Override
    public void engineLoad(InputStream stream, char[] password) throws IOException, NoSuchAlgorithmException,
            CertificateException {
        if (loaded) {
            throw new UnsupportedOperationException();
        }
        loaded = true;
    }

    @Override
    protected KeyStore getKeyStore() {
        return keyStore;
    }

}
