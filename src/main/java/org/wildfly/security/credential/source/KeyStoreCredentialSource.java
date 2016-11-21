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

package org.wildfly.security.credential.source;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;

import org.wildfly.common.Assert;
import org.wildfly.security.SecurityFactory;
import org.wildfly.security._private.ElytronMessages;
import org.wildfly.security.auth.SupportLevel;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.KeyPairCredential;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.credential.PublicKeyCredential;
import org.wildfly.security.credential.SecretKeyCredential;
import org.wildfly.security.credential.X509CertificateChainPrivateCredential;
import org.wildfly.security.credential.X509CertificateChainPublicCredential;
import org.wildfly.security.keystore.PasswordEntry;
import org.wildfly.security.x500.X500;

/**
 * A credential source which is backed by a key store entry.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class KeyStoreCredentialSource implements CredentialSource {
    private final SecurityFactory<KeyStore.Entry> entryFactory;

    /**
     * Construct a new instance.
     *
     * @param keyStore the key store to reference (must not be {@code null})
     * @param alias the name of the key store entry to read from (must not be {@code null})
     * @param protectionParameter the protection parameter to use to access the key store entry, or {@code null} for none
     */
    public KeyStoreCredentialSource(final KeyStore keyStore, final String alias, final KeyStore.ProtectionParameter protectionParameter) {
        Assert.checkNotNullParam("keyStore", keyStore);
        Assert.checkNotNullParam("alias", alias);
        entryFactory = () -> keyStore.getEntry(alias, protectionParameter);
    }

    /**
     * Construct a new instance.
     *
     * @param entryFactory the entry factory to use to instantiate the entry (must not be {@code null})
     */
    public KeyStoreCredentialSource(final SecurityFactory<KeyStore.Entry> entryFactory) {
        Assert.checkNotNullParam("entryFactory", entryFactory);
        this.entryFactory = entryFactory;
    }

    public SupportLevel getCredentialAcquireSupport(final Class<? extends Credential> credentialType, final String algorithmName, final AlgorithmParameterSpec parameterSpec) throws IOException {
        return getCredential(credentialType, algorithmName, parameterSpec) != null ? SupportLevel.SUPPORTED : SupportLevel.UNSUPPORTED;
    }

    public <C extends Credential> C getCredential(final Class<C> credentialType, final String algorithmName, final AlgorithmParameterSpec parameterSpec) throws IOException {
        try {
            final KeyStore.Entry entry = entryFactory.create();
            if (entry == null) {
                return null;
            }
            final Credential credential;
            if (entry instanceof KeyStore.PrivateKeyEntry) {
                final KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) entry;
                final X509Certificate[] certificateChain = X500.asX509CertificateArray(privateKeyEntry.getCertificateChain());
                final X509Certificate firstCert = certificateChain[0];
                final PrivateKey privateKey = privateKeyEntry.getPrivateKey();
                if (credentialType.isAssignableFrom(X509CertificateChainPrivateCredential.class)) {
                    credential = new X509CertificateChainPrivateCredential(privateKey, certificateChain);
                } else if (credentialType.isAssignableFrom(X509CertificateChainPublicCredential.class)) {
                    credential = new X509CertificateChainPublicCredential(certificateChain);
                } else if (credentialType.isAssignableFrom(PublicKeyCredential.class)) {
                    credential = new PublicKeyCredential(firstCert.getPublicKey());
                } else if (credentialType.isAssignableFrom(KeyPairCredential.class)) {
                    credential = new KeyPairCredential(new KeyPair(firstCert.getPublicKey(), privateKey));
                } else {
                    return null;
                }
            } else if (entry instanceof KeyStore.TrustedCertificateEntry) {
                final KeyStore.TrustedCertificateEntry trustedCertificateEntry = (KeyStore.TrustedCertificateEntry) entry;
                final X509Certificate certificate = (X509Certificate) trustedCertificateEntry.getTrustedCertificate();
                // don't support X509CertificateChainPublicCredential because one certificate isn't enough to produce a chain, only to verify it
                if (credentialType.isAssignableFrom(PublicKeyCredential.class)) {
                    credential = new PublicKeyCredential(certificate.getPublicKey());
                } else {
                    return null;
                }
            } else if (entry instanceof KeyStore.SecretKeyEntry) {
                final KeyStore.SecretKeyEntry secretKeyEntry = (KeyStore.SecretKeyEntry) entry;
                if (credentialType.isAssignableFrom(SecretKeyCredential.class)) {
                    credential = new SecretKeyCredential(secretKeyEntry.getSecretKey());
                } else {
                    return null;
                }
            } else if (entry instanceof PasswordEntry) {
                final PasswordEntry passwordEntry = (PasswordEntry) entry;
                if (credentialType.isAssignableFrom(PasswordCredential.class)) {
                    credential = new PasswordCredential(passwordEntry.getPassword());
                } else {
                    return null;
                }
            } else {
                // unrecognized
                return null;
            }
            return credential.castAs(credentialType, algorithmName, parameterSpec);
        } catch (GeneralSecurityException e) {
            throw ElytronMessages.log.unableToReadCredential(e);
        }
    }
}
