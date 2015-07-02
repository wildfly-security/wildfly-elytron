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

import static org.wildfly.security._private.ElytronMessages.log;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.spec.ClearPasswordSpec;

final class WrappingPasswordKeyStoreSpiImpl extends DelegatingKeyStoreSpi {
    private final KeyStore delegate;

    WrappingPasswordKeyStoreSpiImpl(final KeyStore delegate) {
        this.delegate = delegate;
    }

    public Key engineGetKey(final String alias, final char[] password) throws NoSuchAlgorithmException, UnrecoverableKeyException {
        try {
            final Key key = delegate.getKey(alias, password);
            return key instanceof SecretKey ? decoded((SecretKey) key) : null;
        } catch (KeyStoreException e) {
            throw new IllegalStateException(e);
        }
    }

    public Certificate[] engineGetCertificateChain(final String alias) {
        return null;
    }

    public Certificate engineGetCertificate(final String alias) {
        return null;
    }

    public void engineSetKeyEntry(final String alias, final Key key, final char[] password, final Certificate[] chain) throws KeyStoreException {
        if (key instanceof Password) {
            engineSetEntry(alias, new PasswordEntry((Password) key), password == null ? null : new KeyStore.PasswordProtection(password));
        } else {
            throw log.secretKeysNotSupported();
        }
    }

    public void engineSetKeyEntry(final String alias, final byte[] key, final Certificate[] chain) throws KeyStoreException {
        throw log.directKeyStorageNotSupported();
    }

    public void engineSetCertificateEntry(final String alias, final Certificate cert) throws KeyStoreException {
        throw log.directKeyStorageNotSupported();
    }

    public KeyStore.Entry engineGetEntry(final String alias, final KeyStore.ProtectionParameter protParam) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableEntryException {
        final KeyStore.Entry entry = super.engineGetEntry(alias, protParam);
        if (entry instanceof KeyStore.SecretKeyEntry) {
            return new PasswordEntry(decoded(((KeyStore.SecretKeyEntry) entry).getSecretKey()));
        }
        return entry;
    }

    public void engineSetEntry(final String alias, final KeyStore.Entry entry, final KeyStore.ProtectionParameter protParam) throws KeyStoreException {
        if (! (entry instanceof PasswordEntry)) {
            throw log.onlyPasswordStorageIsSupported();
        }
        try {
            delegate.setEntry(alias, new KeyStore.SecretKeyEntry(encoded(((PasswordEntry) entry).getPassword())), protParam);
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new KeyStoreException(e);
        }
    }

    public boolean engineEntryInstanceOf(final String alias, final Class<? extends KeyStore.Entry> entryClass) {
        try {
            return entryClass == PasswordEntry.class && delegate.entryInstanceOf(alias, KeyStore.SecretKeyEntry.class);
        } catch (KeyStoreException e) {
            throw new IllegalStateException(e);
        }
    }

    public boolean engineIsCertificateEntry(final String alias) {
        return false;
    }

    public String engineGetCertificateAlias(final Certificate cert) {
        return null;
    }

    private static Password decoded(final SecretKey key) throws NoSuchAlgorithmException, KeyStoreException {
        final PasswordFactory passwordFactory = PasswordFactory.getInstance("clear");
        try {
            return passwordFactory.generatePassword(new ClearPasswordSpec(new String(key.getEncoded(), StandardCharsets.UTF_8).toCharArray()));
        } catch (InvalidKeySpecException e) {
            throw new KeyStoreException(e);
        }
    }

    private static SecretKey encoded(final Password password) throws InvalidKeySpecException, NoSuchAlgorithmException {
        final PasswordFactory factory = PasswordFactory.getInstance("clear");
        final ClearPasswordSpec spec = factory.getKeySpec(password, ClearPasswordSpec.class);
        final char[] encodedPassword = spec.getEncodedPassword();
        return new SecretKeySpec(new String(encodedPassword).getBytes(StandardCharsets.UTF_8), "password");
    }

    @Override
    protected KeyStore getKeyStore() {
        return delegate;
    }
}
