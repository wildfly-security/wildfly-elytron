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

package org.wildfly.security.auth.provider;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import javax.crypto.SecretKey;

import org.wildfly.security.authz.AuthorizationIdentity;
import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.auth.server.SupportLevel;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.KeyPairCredential;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.credential.SecretKeyCredential;
import org.wildfly.security.credential.X509CertificateChainPrivateCredential;
import org.wildfly.security.credential.X509CertificateChainPublicCredential;
import org.wildfly.security.evidence.Evidence;
import org.wildfly.security.evidence.PasswordGuessEvidence;
import org.wildfly.security.keystore.PasswordEntry;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactory;

/**
 * A {@link KeyStore} backed {@link SecurityRealm} implementation.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class KeyStoreBackedSecurityRealm implements SecurityRealm {
    private final KeyStore keyStore;

    public final char USER_CREDENTIAL_DELIMITER = '|';

    /**
     * Construct a new instance.
     *
     * @param keyStore the keystore to use to back this realm
     */
    public KeyStoreBackedSecurityRealm(final KeyStore keyStore) {
        this.keyStore = keyStore;
    }

    @Override
    public RealmIdentity createRealmIdentity(final String name) throws RealmUnavailableException {
        return new KeyStoreRealmIdentity(name);
    }

    @Override
    public SupportLevel getCredentialAcquireSupport(final String credentialName) {
        return SupportLevel.POSSIBLY_SUPPORTED;
    }

    private KeyStore.Entry getEntry(String name) {
        try {
            return keyStore.getEntry(name, null);
        } catch (NoSuchAlgorithmException e) {
            return null;
        } catch (UnrecoverableEntryException e) {
            return null;
        } catch (KeyStoreException e) {
            return null;
        }
    }

    private class KeyStoreRealmIdentity implements RealmIdentity {

        private final String name;

        private KeyStoreRealmIdentity(final String name) {
            this.name = name;
        }

        @Override
        public SupportLevel getCredentialAcquireSupport(final String credentialName) {
            final KeyStore.Entry entry = getEntry(name + USER_CREDENTIAL_DELIMITER + credentialName);
            if (entry == null) {
                return SupportLevel.UNSUPPORTED;
            }
            return SupportLevel.SUPPORTED;
        }

        @Override
        public <C extends Credential> C getCredential(final String credentialName, final Class<C> credentialType) {
            final KeyStore.Entry entry = getEntry(name + USER_CREDENTIAL_DELIMITER + credentialName);
            if (entry == null) return null;
            if (entry instanceof PasswordEntry) {
                final Password password = ((PasswordEntry) entry).getPassword();
                if (credentialType.isAssignableFrom(PasswordCredential.class)) {
                    return credentialType.cast(new PasswordCredential(password));
                }
            } else if (entry instanceof KeyStore.PrivateKeyEntry) {
                final KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) entry;
                final PrivateKey privateKey = privateKeyEntry.getPrivateKey();
                final Certificate certificate = privateKeyEntry.getCertificate();
                if (credentialType.isAssignableFrom(X509CertificateChainPublicCredential.class) && certificate instanceof X509Certificate) {
                    return credentialType.cast(new X509CertificateChainPublicCredential((X509Certificate) certificate));
                } else if (credentialType.isAssignableFrom(X509CertificateChainPrivateCredential.class) && certificate instanceof X509Certificate) {
                    return credentialType.cast(new X509CertificateChainPrivateCredential(privateKey, (X509Certificate) certificate));
                } else if (credentialType.isAssignableFrom(KeyPairCredential.class)) {
                    return credentialType.cast(new KeyPairCredential(new KeyPair(certificate.getPublicKey(), privateKey)));
                }
            } else if (entry instanceof KeyStore.TrustedCertificateEntry) {
                final Certificate certificate = ((KeyStore.TrustedCertificateEntry) entry).getTrustedCertificate();
                if (credentialType.isAssignableFrom(X509CertificateChainPublicCredential.class) && certificate instanceof X509Certificate) {
                    return credentialType.cast(new X509CertificateChainPublicCredential((X509Certificate) certificate));
                }
            } else if (entry instanceof KeyStore.SecretKeyEntry) {
                final SecretKey secretKey = ((KeyStore.SecretKeyEntry) entry).getSecretKey();
                if (credentialType.isAssignableFrom(SecretKeyCredential.class)) {
                    return credentialType.cast(new SecretKeyCredential(secretKey));
                }
            }
            return null;
        }

        @Override
        public Credential getCredential(String credentialName) throws RealmUnavailableException {
            return getCredential(credentialName, Credential.class);
        }

        @Override
        public AuthorizationIdentity getAuthorizationIdentity() {
            return new AuthorizationIdentity() {
            };
        }

        public boolean verifyEvidence(final String credentialName, final Evidence evidence) throws RealmUnavailableException {
            final KeyStore.Entry entry = getEntry(name + USER_CREDENTIAL_DELIMITER + credentialName);
            if (entry == null) return false;
            if (entry instanceof PasswordEntry) {
                final Password password = ((PasswordEntry) entry).getPassword();
                if (evidence instanceof PasswordGuessEvidence) try {
                    PasswordFactory passwordFactory = PasswordFactory.getInstance(password.getAlgorithm());
                    return passwordFactory.verify(passwordFactory.translate(password), ((PasswordGuessEvidence) evidence).getGuess());
                } catch (NoSuchAlgorithmException | InvalidKeyException e) {
                    throw new RealmUnavailableException(e);
                } else {
                    return false;
                }
            } else {
                // no other known verifiable credential types
                return false;
            }
        }

        public boolean exists() throws RealmUnavailableException {
            return true;
        }
    }
}
