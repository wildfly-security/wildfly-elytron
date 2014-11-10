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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.Date;
import java.util.Enumeration;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.spec.ClearPasswordSpec;

final class WrappingPasswordKeyStoreSpiImpl extends KeyStoreSpi {
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

    public Date engineGetCreationDate(final String alias) {
        try {
            return delegate.getCreationDate(alias);
        } catch (KeyStoreException e) {
            throw new IllegalStateException(e);
        }
    }

    public void engineSetKeyEntry(final String alias, final Key key, final char[] password, final Certificate[] chain) throws KeyStoreException {
        if (key instanceof Password) {
            engineSetEntry(alias, new PasswordEntry((Password) key), password == null ? null : new KeyStore.PasswordProtection(password));
        } else {
            throw new KeyStoreException("Secret keys not supported");
        }
    }

    public void engineSetKeyEntry(final String alias, final byte[] key, final Certificate[] chain) throws KeyStoreException {
        throw new KeyStoreException("Direct key storage not supported");
    }

    public void engineSetCertificateEntry(final String alias, final Certificate cert) throws KeyStoreException {
        throw new KeyStoreException("Direct key storage not supported");
    }

    public void engineDeleteEntry(final String alias) throws KeyStoreException {
        delegate.deleteEntry(alias);
    }

    public Enumeration<String> engineAliases() {
        try {
            return delegate.aliases();
        } catch (KeyStoreException e) {
            throw new IllegalStateException(e);
        }
    }

    public boolean engineContainsAlias(final String alias) {
        try {
            return delegate.containsAlias(alias);
        } catch (KeyStoreException e) {
            throw new IllegalStateException(e);
        }
    }

    public int engineSize() {
        try {
            return delegate.size();
        } catch (KeyStoreException e) {
            throw new IllegalStateException(e);
        }
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
            throw new KeyStoreException("Only password storage is supported");
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

    public boolean engineIsKeyEntry(final String alias) {
        try {
            return delegate.isKeyEntry(alias);
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

    public void engineStore(final OutputStream stream, final char[] password) throws IOException, NoSuchAlgorithmException, CertificateException {
        try {
            delegate.store(stream, password);
        } catch (KeyStoreException e) {
            throw new IllegalStateException(e);
        }
    }

    public void engineStore(final KeyStore.LoadStoreParameter param) throws IOException, NoSuchAlgorithmException, CertificateException {
        try {
            delegate.store(param);
        } catch (KeyStoreException e) {
            throw new IllegalStateException(e);
        }
    }

    public void engineLoad(final InputStream stream, final char[] password) throws IOException, NoSuchAlgorithmException, CertificateException {
        delegate.load(stream, password);
    }

    public void engineLoad(final KeyStore.LoadStoreParameter param) throws IOException, NoSuchAlgorithmException, CertificateException {
        delegate.load(param);
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
}
