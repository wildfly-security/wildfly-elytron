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

package org.wildfly.security.auth.realm;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.Provider;
import java.security.Security;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Enumeration;
import java.util.function.Supplier;

import javax.security.auth.x500.X500Principal;

import org.wildfly.common.Assert;
import org.wildfly.security._private.ElytronMessages;
import org.wildfly.security.auth.principal.NamePrincipal;
import org.wildfly.security.authz.AuthorizationIdentity;
import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.auth.SupportLevel;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.evidence.Evidence;
import org.wildfly.security.x500.util.X500PrincipalUtil;

/**
 * A {@link KeyStore} backed {@link SecurityRealm} implementation.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class KeyStoreBackedSecurityRealm implements SecurityRealm {

    private final Supplier<Provider[]> providers;
    private final KeyStore keyStore;

    /**
     * Construct a new instance.
     *
     * @param keyStore the keystore to use to back this realm
     */
    public KeyStoreBackedSecurityRealm(final KeyStore keyStore) {
        this(keyStore, Security::getProviders);
    }

    /**
     * Construct a new instance.
     *
     * @param keyStore the keystore to use to back this realm
     * @param providers A supplier of providers for use by this realm
     */
    public KeyStoreBackedSecurityRealm(final KeyStore keyStore, final Supplier<Provider[]> providers) {
        this.keyStore = keyStore;
        this.providers = providers;
    }

    @Override
    public RealmIdentity getRealmIdentity(final Principal principal) throws RealmUnavailableException {
        if (principal instanceof NamePrincipal) {
            return new KeyStoreRealmIdentity(principal.getName());
        } else {
            final X500Principal x500Principal = X500PrincipalUtil.asX500Principal(principal);
            if (x500Principal == null) {
                return RealmIdentity.NON_EXISTENT;
            } else {
                final KeyStore keyStore = this.keyStore;
                try {
                    final Enumeration<String> aliases = keyStore.aliases();
                    while (aliases.hasMoreElements()) {
                        final String alias = aliases.nextElement();
                        if (keyStore.isCertificateEntry(alias)) {
                            final Certificate certificate = keyStore.getCertificate(alias);
                            if (certificate instanceof X509Certificate && x500Principal.equals(X500PrincipalUtil.asX500Principal(((X509Certificate) certificate).getSubjectX500Principal()))) {
                                return new KeyStoreRealmIdentity(alias);
                            }
                        }
                    }
                } catch (KeyStoreException e) {
                    throw ElytronMessages.log.failedToReadKeyStore(e);
                }
                return RealmIdentity.NON_EXISTENT;
            }
        }
    }

    @Override
    public SupportLevel getCredentialAcquireSupport(final Class<? extends Credential> credentialType, final String algorithmName, final AlgorithmParameterSpec parameterSpec) throws RealmUnavailableException {
        Assert.checkNotNullParam("credentialType", credentialType);
        return SupportLevel.POSSIBLY_SUPPORTED;
    }

    @Override
    public SupportLevel getEvidenceVerifySupport(final Class<? extends Evidence> evidenceType, final String algorithmName) throws RealmUnavailableException {
        Assert.checkNotNullParam("evidenceType", evidenceType);
        return SupportLevel.POSSIBLY_SUPPORTED;
    }

    private KeyStore.Entry getEntry(String name) {
        try {
            return keyStore.getEntry(name, null);
        } catch (NoSuchAlgorithmException | UnrecoverableEntryException | KeyStoreException e) {
            ElytronMessages.log.tracef(e, "Obtaining entry [%s] from KeyStore failed", name);
            return null;
        }
    }

    private class KeyStoreRealmIdentity implements RealmIdentity {

        private final String name;

        private KeyStoreRealmIdentity(final String name) {
            this.name = name;
        }

        public Principal getRealmIdentityPrincipal() {
            return new NamePrincipal(name);
        }

        @Override
        public SupportLevel getCredentialAcquireSupport(final Class<? extends Credential> credentialType, final String algorithmName, final AlgorithmParameterSpec parameterSpec) throws RealmUnavailableException {
            final KeyStore.Entry entry = getEntry(name);
            if (entry == null) {
                return SupportLevel.UNSUPPORTED;
            }
            final Credential credential = Credential.fromKeyStoreEntry(entry);
            return credential != null && credential.matches(credentialType, algorithmName, parameterSpec) ? SupportLevel.SUPPORTED : SupportLevel.UNSUPPORTED;
        }

        @Override
        public <C extends Credential> C getCredential(final Class<C> credentialType, final String algorithmName, final AlgorithmParameterSpec parameterSpec) throws RealmUnavailableException {
            Assert.checkNotNullParam("credentialType", credentialType);
            final KeyStore.Entry entry = getEntry(name);
            if (entry == null) return null;
            final Credential credential = Credential.fromKeyStoreEntry(entry);
            return credential != null ? credential.castAs(credentialType, algorithmName, parameterSpec) : null;
        }

        @Override
        public <C extends Credential> C getCredential(final Class<C> credentialType, final String algorithmName) throws RealmUnavailableException {
            return getCredential(credentialType, algorithmName, null);
        }

        @Override
        public <C extends Credential> C getCredential(final Class<C> credentialType) throws RealmUnavailableException {
            return getCredential(credentialType, null);
        }

        @Override
        public AuthorizationIdentity getAuthorizationIdentity() {
            return AuthorizationIdentity.EMPTY;
        }

        @Override
        public SupportLevel getEvidenceVerifySupport(final Class<? extends Evidence> evidenceType, final String algorithmName) throws RealmUnavailableException {
            final KeyStore.Entry entry = getEntry(name);
            if (entry == null) {
                return SupportLevel.UNSUPPORTED;
            }
            final Credential credential = Credential.fromKeyStoreEntry(entry);
            if (credential != null && credential.canVerify(evidenceType, algorithmName)) {
                return SupportLevel.SUPPORTED;
            }
            return SupportLevel.UNSUPPORTED;
        }

        @Override
        public boolean verifyEvidence(final Evidence evidence) throws RealmUnavailableException {
            final KeyStore.Entry entry = getEntry(name);
            if (entry == null) {
                ElytronMessages.log.tracef("Evidence verification failed - alias [%s] does not exist in KeyStore", name);
                return false;
            }
            final Credential credential = Credential.fromKeyStoreEntry(entry);
            if (credential != null && credential.canVerify(evidence) && credential.verify(providers, evidence)) {
                ElytronMessages.log.tracef("Evidence verification succeed for alias [%s]", name);
                return true;
            }
            ElytronMessages.log.tracef("Evidence verification failed - credential of alias [%s] rejected it", name);
            return false;
        }

        public boolean exists() throws RealmUnavailableException {
            return getEntry(name) != null;
        }
    }
}
