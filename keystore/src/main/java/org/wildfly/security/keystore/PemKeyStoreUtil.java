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

import static org.wildfly.security.x500.cert.util.KeyUtil.getDefaultCompatibleSignatureAlgorithmName;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.wildfly.common.iteration.CodePointIterator;
import org.wildfly.security.pem.Pem;
import org.wildfly.security.pem.PemEntry;

final class PemKeyStoreUtil {

    static final String DEFAULT_ALIAS = "tls";
    static final int MAX_PEM_CONTENT_SIZE = 10 * 1024 * 1024;

    private static final String BACKING_KEY_STORE_TYPE = "PKCS12";
    private static final byte[] KEY_MATCH_PROBE = "WildFly Elytron PEM key match probe".getBytes(StandardCharsets.UTF_8);

    private PemKeyStoreUtil() {
    }

    static PemEntries loadPemEntries(InputStream is) throws IOException {
        PrivateKey privateKey = null;
        List<X509Certificate> certificates = new ArrayList<X509Certificate>();
        byte[] pem = readAllBytes(is);
        try {
            for (Iterator<PemEntry<?>> it = Pem.parsePemContent(CodePointIterator.ofUtf8Bytes(pem)); it.hasNext(); ) {
                Object entry = it.next().getEntry();
                if (entry instanceof PrivateKey) {
                    if (privateKey != null) {
                        throw new IOException("PEM content contains more than one private key");
                    }
                    privateKey = (PrivateKey) entry;
                } else if (entry instanceof X509Certificate) {
                    certificates.add((X509Certificate) entry);
                } else if (entry instanceof PublicKey) {
                    throw new IOException("PEM content contains an unsupported public key entry");
                }
            }
        } catch (IllegalArgumentException e) {
            throw new IOException("Unable to parse PEM content", e);
        }
        return new PemEntries(privateKey, certificates);
    }

    static KeyStore createKeyStore(PemEntries pemEntries, String alias, char[] password) throws IOException, NoSuchAlgorithmException, CertificateException {
        KeyStore keyStore = createEmptyKeyStore();
        PrivateKey privateKey = pemEntries.getPrivateKey();
        List<X509Certificate> certificates = pemEntries.getCertificates();
        try {
            if (privateKey != null) {
                if (certificates.isEmpty()) {
                    throw new CertificateException("PEM content does not contain an X.509 certificate");
                }
                X509Certificate certificate = certificates.get(0);
                validatePrivateKeyMatchesCertificate(privateKey, certificate);
                String keyAlias = alias != null ? alias : certificate.getSubjectX500Principal().getName();
                keyStore.setKeyEntry(keyAlias, privateKey, password != null ? password : new char[0], certificates.toArray(new Certificate[0]));
            } else {
                for (X509Certificate certificate : certificates) {
                    String subjectName = certificate.getSubjectX500Principal().getName();
                    String certificateAlias = subjectName;
                    int i = 1;
                    while (keyStore.containsAlias(certificateAlias)) {
                        certificateAlias = subjectName + "-" + i++;
                    }
                    keyStore.setCertificateEntry(certificateAlias, certificate);
                }
            }
        } catch (KeyStoreException e) {
            throw new IOException(e);
        }
        return keyStore;
    }

    static void validatePrivateKeyMatchesCertificate(PrivateKey privateKey, X509Certificate certificate) throws CertificateException {
        try {
            String signatureAlgorithm = getDefaultCompatibleSignatureAlgorithmName(privateKey);
            if (signatureAlgorithm == null) {
                throw new CertificateException("Unable to determine a compatible signature algorithm for private key algorithm " + privateKey.getAlgorithm());
            }
            Signature signature = Signature.getInstance(signatureAlgorithm);
            signature.initSign(privateKey);
            signature.update(KEY_MATCH_PROBE);
            byte[] signed = signature.sign();

            signature.initVerify(certificate.getPublicKey());
            signature.update(KEY_MATCH_PROBE);
            if (! signature.verify(signed)) {
                throw new CertificateException("Private key does not match certificate public key");
            }
        } catch (CertificateException e) {
            throw e;
        } catch (IllegalArgumentException | GeneralSecurityException e) {
            throw new CertificateException("Private key does not match certificate public key", e);
        }
    }

    private static KeyStore createEmptyKeyStore() throws IOException, NoSuchAlgorithmException, CertificateException {
        try {
            KeyStore keyStore = KeyStore.getInstance(BACKING_KEY_STORE_TYPE);
            keyStore.load(null, null);
            return keyStore;
        } catch (KeyStoreException e) {
            throw new IOException(e);
        }
    }

    private static byte[] readAllBytes(InputStream inputStream) throws IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        int readBytes = inputStream.read(buffer);

        while (readBytes != -1) {
            if (outputStream.size() > MAX_PEM_CONTENT_SIZE - readBytes) {
                throw new IOException("PEM content exceeds maximum size of " + MAX_PEM_CONTENT_SIZE + " bytes");
            }
            outputStream.write(buffer, 0, readBytes);
            readBytes = inputStream.read(buffer);
        }
        return outputStream.toByteArray();
    }

    static final class PemEntries {

        private final PrivateKey privateKey;
        private final List<X509Certificate> certificates;

        PemEntries(PrivateKey privateKey, List<X509Certificate> certificates) {
            this.privateKey = privateKey;
            this.certificates = certificates;
        }

        PrivateKey getPrivateKey() {
            return privateKey;
        }

        List<X509Certificate> getCertificates() {
            return certificates;
        }
    }
}
