/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2026 Red Hat, Inc., and individual contributors
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
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;

/**
 * A read-only PEM {@link KeyStore} implementation.  Loading from an {@link InputStream} accepts combined PEM
 * certificate and unencrypted private-key content.  Loading separate certificate and private-key files requires a
 * {@link PemKeyStoreLoadParameter}.  A {@code null} input stream initializes an empty KeyStore.  Loading is atomic: if
 * a load attempt fails, any material from the last successful load remains available.
 */
public final class PemKeyStoreSpi extends KeyStoreSpi {

    private KeyStore keyStore;

    @Override
    public Key engineGetKey(String alias, char[] password) throws NoSuchAlgorithmException, UnrecoverableKeyException {
        try {
            return getKeyStore().getKey(alias, password);
        } catch (KeyStoreException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public KeyStore.Entry engineGetEntry(String alias, KeyStore.ProtectionParameter protParam) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableEntryException {
        return getKeyStore().getEntry(alias, protParam);
    }

    @Override
    public boolean engineEntryInstanceOf(String alias, Class<? extends KeyStore.Entry> entryClass) {
        try {
            return getKeyStore().entryInstanceOf(alias, entryClass);
        } catch (KeyStoreException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public Certificate[] engineGetCertificateChain(String alias) {
        try {
            return getKeyStore().getCertificateChain(alias);
        } catch (KeyStoreException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public Certificate engineGetCertificate(String alias) {
        try {
            return getKeyStore().getCertificate(alias);
        } catch (KeyStoreException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public Date engineGetCreationDate(String alias) {
        try {
            return getKeyStore().getCreationDate(alias);
        } catch (KeyStoreException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public void engineSetKeyEntry(String alias, Key key, char[] password, Certificate[] chain) throws KeyStoreException {
        throw readOnly();
    }

    @Override
    public void engineSetKeyEntry(String alias, byte[] key, Certificate[] chain) throws KeyStoreException {
        throw readOnly();
    }

    @Override
    public void engineSetCertificateEntry(String alias, Certificate cert) throws KeyStoreException {
        throw readOnly();
    }

    @Override
    public void engineSetEntry(String alias, KeyStore.Entry entry, KeyStore.ProtectionParameter protParam) throws KeyStoreException {
        throw readOnly();
    }

    @Override
    public void engineDeleteEntry(String alias) throws KeyStoreException {
        throw readOnly();
    }

    @Override
    public Enumeration<String> engineAliases() {
        try {
            return getKeyStore().aliases();
        } catch (KeyStoreException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public boolean engineContainsAlias(String alias) {
        try {
            return getKeyStore().containsAlias(alias);
        } catch (KeyStoreException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public int engineSize() {
        try {
            return getKeyStore().size();
        } catch (KeyStoreException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public boolean engineIsKeyEntry(String alias) {
        try {
            return getKeyStore().isKeyEntry(alias);
        } catch (KeyStoreException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public boolean engineIsCertificateEntry(String alias) {
        try {
            return getKeyStore().isCertificateEntry(alias);
        } catch (KeyStoreException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public String engineGetCertificateAlias(Certificate cert) {
        try {
            return getKeyStore().getCertificateAlias(cert);
        } catch (KeyStoreException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public void engineStore(OutputStream stream, char[] password) throws IOException, NoSuchAlgorithmException, CertificateException {
        throw new UnsupportedOperationException("PEM KeyStore does not support storing");
    }

    @Override
    public void engineStore(KeyStore.LoadStoreParameter param) throws IOException, NoSuchAlgorithmException, CertificateException {
        throw new UnsupportedOperationException("PEM KeyStore does not support storing");
    }

    @Override
    public void engineLoad(InputStream stream, char[] password) throws IOException, NoSuchAlgorithmException, CertificateException {
        if (stream == null) {
            keyStore = PemKeyStoreUtil.createKeyStore(new PemKeyStoreUtil.PemEntries(null, Collections.<X509Certificate>emptyList()), null, password);
            return;
        }
        keyStore = PemKeyStoreUtil.createKeyStore(PemKeyStoreUtil.loadPemEntries(stream), null, password);
    }

    @Override
    public void engineLoad(KeyStore.LoadStoreParameter param) throws IOException, NoSuchAlgorithmException, CertificateException {
        if (! (param instanceof PemKeyStoreLoadParameter)) {
            throw new IOException("PEM KeyStore requires PemKeyStoreLoadParameter");
        }
        PemKeyStoreLoadParameter pemParameter = (PemKeyStoreLoadParameter) param;
        char[] password = getPassword(pemParameter);
        PemKeyStoreUtil.PemEntries certificateEntries = loadPemFile(pemParameter.getCertificatePath(), "certificate");
        PemKeyStoreUtil.PemEntries privateKeyEntries = loadPemFile(pemParameter.getPrivateKeyPath(), "private key");

        List<X509Certificate> certificates = certificateEntries.getCertificates();
        PrivateKey privateKey = privateKeyEntries.getPrivateKey();
        if (certificates.isEmpty()) {
            throw new CertificateException("PEM certificate file does not contain an X.509 certificate");
        }
        if (privateKey == null) {
            throw new IOException("PEM private key file does not contain a private key");
        }
        if (certificateEntries.getPrivateKey() != null) {
            throw new IOException("PEM certificate file must not contain a private key: \"" + pemParameter.getCertificatePath() + "\"");
        }
        if (! privateKeyEntries.getCertificates().isEmpty()) {
            throw new IOException("PEM private key file must not contain an X.509 certificate: \"" + pemParameter.getPrivateKeyPath() + "\"");
        }
        keyStore = PemKeyStoreUtil.createKeyStore(new PemKeyStoreUtil.PemEntries(privateKey, certificates), pemParameter.getAlias(), password);
    }

    private PemKeyStoreUtil.PemEntries loadPemFile(Path path, String role) throws IOException {
        if (! Files.exists(path)) {
            throw new IOException("PEM " + role + " file does not exist: \"" + path + "\"");
        }
        if (! Files.isRegularFile(path)) {
            throw new IOException("PEM " + role + " path is not a regular file: \"" + path + "\"");
        }
        if (! Files.isReadable(path)) {
            throw new IOException("PEM " + role + " file is not readable: \"" + path + "\"");
        }
        try (InputStream stream = Files.newInputStream(path)) {
            return PemKeyStoreUtil.loadPemEntries(stream);
        } catch (IOException e) {
            throw new IOException("Unable to load PEM " + role + " file \"" + path + "\"", e);
        }
    }

    private char[] getPassword(PemKeyStoreLoadParameter pemParameter) throws IOException {
        KeyStore.ProtectionParameter protectionParameter = pemParameter.getProtectionParameter();
        if (protectionParameter == null) {
            return new char[0];
        }
        if (! (protectionParameter instanceof KeyStore.PasswordProtection)) {
            throw new IOException("PEM KeyStore only supports KeyStore.PasswordProtection");
        }
        char[] password = ((KeyStore.PasswordProtection) protectionParameter).getPassword();
        return password != null ? password : new char[0];
    }

    private KeyStore getKeyStore() {
        if (keyStore == null) {
            throw new IllegalStateException("PEM KeyStore has not been loaded");
        }
        return keyStore;
    }

    private KeyStoreException readOnly() {
        return new KeyStoreException("PEM KeyStore is read-only");
    }
}
