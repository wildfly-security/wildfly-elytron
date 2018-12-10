/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2014 Red Hat, Inc., and individual contributors
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

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.wildfly.security._private.ElytronMessages;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.interfaces.ClearPassword;

final class WrappingPasswordKeyStoreSpiImpl extends DelegatingKeyStoreSpi {
    private final KeyStore delegate;

    WrappingPasswordKeyStoreSpiImpl(final KeyStore delegate) {
        this.delegate = delegate;
    }

    public Key engineGetKey(final String alias, final char[] password) throws NoSuchAlgorithmException, UnrecoverableKeyException {
        try {
            final Key key = delegate.getKey(alias, password);
            return key instanceof SecretKey && "password".equals(key.getAlgorithm()) ? decoded((SecretKey) key) : key;
        } catch (KeyStoreException e) {
            throw new IllegalStateException(e);
        }
    }

    public Certificate[] engineGetCertificateChain(final String alias) {
        try {
            return delegate.getCertificateChain(alias);
        } catch (KeyStoreException e) {
            return null;
        }
    }

    public Certificate engineGetCertificate(final String alias) {
        try {
            return delegate.getCertificate(alias);
        } catch (KeyStoreException e) {
            return null;
        }
    }

    public void engineSetKeyEntry(final String alias, final Key key, final char[] password, final Certificate[] chain) throws KeyStoreException {
        if (key instanceof Password) {
            engineSetEntry(alias, new PasswordEntry((Password) key), password == null ? null : new KeyStore.PasswordProtection(password));
        } else {
            delegate.setKeyEntry(alias, key, password, chain);
        }
    }

    public void engineSetKeyEntry(final String alias, final byte[] key, final Certificate[] chain) throws KeyStoreException {
        delegate.setKeyEntry(alias, key, chain);
    }

    public void engineSetCertificateEntry(final String alias, final Certificate cert) throws KeyStoreException {
        delegate.setCertificateEntry(alias, cert);
    }

    public KeyStore.Entry engineGetEntry(final String alias, final KeyStore.ProtectionParameter protParam) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableEntryException {
        final KeyStore.Entry entry = delegate.getEntry(alias, protParam);
        if (entry instanceof KeyStore.SecretKeyEntry) {
            final SecretKey secretKey = ((KeyStore.SecretKeyEntry) entry).getSecretKey();
            if ("password".equals(secretKey.getAlgorithm())) {
                return new PasswordEntry(decoded(secretKey));
            }
        }
        return entry;
    }

    public void engineSetEntry(final String alias, final KeyStore.Entry entry, final KeyStore.ProtectionParameter protParam) throws KeyStoreException {
        if (entry instanceof PasswordEntry) try {
            delegate.setEntry(alias, new KeyStore.SecretKeyEntry(encoded(((PasswordEntry) entry).getPassword())), protParam);
        } catch (InvalidKeyException e) {
            throw new KeyStoreException(e);
        }else {
            delegate.setEntry(alias, entry, protParam);
        }
    }

    public boolean engineEntryInstanceOf(final String alias, final Class<? extends KeyStore.Entry> entryClass) {
        try {
            return entryClass == PasswordEntry.class && delegate.entryInstanceOf(alias, KeyStore.SecretKeyEntry.class) || delegate.entryInstanceOf(alias, entryClass);
        } catch (KeyStoreException e) {
            throw new IllegalStateException(e);
        }
    }

    public boolean engineIsCertificateEntry(final String alias) {
        try {
            return delegate.isCertificateEntry(alias);
        } catch (KeyStoreException e) {
            return false;
        }
    }

    public String engineGetCertificateAlias(final Certificate cert) {
        try {
            return delegate.getCertificateAlias(cert);
        } catch (KeyStoreException e) {
            return null;
        }
    }

    private static Password decoded(final SecretKey key) {
        return ClearPassword.createRaw(ClearPassword.ALGORITHM_CLEAR, new String(key.getEncoded(), StandardCharsets.UTF_8).toCharArray());
    }

    private static SecretKey encoded(final Password password) throws InvalidKeyException {
        if (password instanceof ClearPassword) {
            return new SecretKeySpec(new String(((ClearPassword)password).getPassword()).getBytes(StandardCharsets.UTF_8), "password");
        } else {
            throw ElytronMessages.log.invalidKeyUnknownUnknownPasswordTypeOrAlgorithm();
        }
    }

    @Override
    protected KeyStore getKeyStore() {
        return delegate;
    }
}
