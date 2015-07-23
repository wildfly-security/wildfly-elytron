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
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import javax.crypto.SecretKey;
import javax.security.auth.x500.X500PrivateCredential;

import org.wildfly.security.authz.AuthorizationIdentity;
import org.wildfly.security.auth.server.CredentialSupport;
import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.auth.server.SecurityRealm;
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
    public CredentialSupport getCredentialSupport(final Class<?> credentialType, final String algorithmName) {
        return credentialType.isAssignableFrom(SecretKey.class) || credentialType.isAssignableFrom(Password.class) || credentialType.isAssignableFrom(X500PrivateCredential.class) ? CredentialSupport.UNKNOWN : CredentialSupport.UNSUPPORTED;
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

        public String getName() {
            return name;
        }

        @Override
        public CredentialSupport getCredentialSupport(Class<?> credentialType, final String algorithmName) {
            final KeyStore.Entry entry = getEntry(name);
            if (entry == null) {
                return CredentialSupport.UNSUPPORTED;
            }
            if (entry instanceof PasswordEntry) {
                final Password password = ((PasswordEntry) entry).getPassword();
                if (credentialType.isInstance(password)) {
                    return CredentialSupport.FULLY_SUPPORTED;
                } else {
                    return CredentialSupport.UNSUPPORTED;
                }
            } else if (entry instanceof KeyStore.PrivateKeyEntry) {
                final KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) entry;
                final PrivateKey privateKey = privateKeyEntry.getPrivateKey();
                final Certificate certificate = privateKeyEntry.getCertificate();
                return credentialType.isInstance(privateKey) || credentialType.isInstance(certificate) || certificate instanceof X509Certificate && X500PrivateCredential.class.isAssignableFrom(credentialType) ? CredentialSupport.FULLY_SUPPORTED : CredentialSupport.UNSUPPORTED;
            } else if (entry instanceof KeyStore.TrustedCertificateEntry) {
                return credentialType.isInstance(((KeyStore.TrustedCertificateEntry) entry).getTrustedCertificate()) ? CredentialSupport.FULLY_SUPPORTED : CredentialSupport.UNSUPPORTED;
            } else if (entry instanceof KeyStore.SecretKeyEntry) {
                return credentialType.isInstance(((KeyStore.SecretKeyEntry) entry).getSecretKey()) ? CredentialSupport.FULLY_SUPPORTED : CredentialSupport.UNSUPPORTED;
            }
            return CredentialSupport.UNSUPPORTED;
        }

        @Override
        public <C> C getCredential(final Class<C> credentialType, final String algorithmName) {
            final KeyStore.Entry entry = getEntry(name);
            if (entry == null) return null;
            if (entry instanceof PasswordEntry) {
                final Password password = ((PasswordEntry) entry).getPassword();
                if (credentialType.isInstance(password)) {
                    return credentialType.cast(password);
                }
            }else if (entry instanceof KeyStore.PrivateKeyEntry) {
                final KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) entry;
                final PrivateKey privateKey = privateKeyEntry.getPrivateKey();
                final Certificate certificate = privateKeyEntry.getCertificate();
                if (credentialType.isInstance(privateKey)) {
                    return credentialType.cast(privateKey);
                } else if (credentialType.isInstance(certificate)) {
                    return credentialType.cast(certificate);
                } else if (credentialType.isAssignableFrom(X500PrivateCredential.class) && certificate instanceof X509Certificate) {
                    return credentialType.cast(new X500PrivateCredential((X509Certificate) certificate, privateKey, name));
                }
            } else if (entry instanceof KeyStore.TrustedCertificateEntry) {
                final Certificate certificate = ((KeyStore.TrustedCertificateEntry) entry).getTrustedCertificate();
                if (credentialType.isInstance(certificate)) {
                    return credentialType.cast(certificate);
                }
            } else if (entry instanceof KeyStore.SecretKeyEntry) {
                final SecretKey secretKey = ((KeyStore.SecretKeyEntry) entry).getSecretKey();
                if (credentialType.isInstance(secretKey)) {
                    return credentialType.cast(secretKey);
                }
            }
            return null;
        }

        @Override
        public AuthorizationIdentity getAuthorizationIdentity() {
            return new AuthorizationIdentity() {
            };
        }

        public boolean verifyCredential(final Object credential) throws RealmUnavailableException {
            final KeyStore.Entry entry = getEntry(name);
            if (entry == null) return false;
            if (entry instanceof PasswordEntry) {
                final Password password = ((PasswordEntry) entry).getPassword();
                if (credential instanceof char[]) try {
                    PasswordFactory passwordFactory = PasswordFactory.getInstance(password.getAlgorithm());
                    return passwordFactory.verify(passwordFactory.translate(password), (char[]) credential);
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
