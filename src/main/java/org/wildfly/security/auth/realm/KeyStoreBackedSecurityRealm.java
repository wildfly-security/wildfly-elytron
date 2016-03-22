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
import java.security.UnrecoverableEntryException;

import org.wildfly.common.Assert;
import org.wildfly.security.authz.AuthorizationIdentity;
import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.auth.server.SupportLevel;
import org.wildfly.security.credential.AlgorithmCredential;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.evidence.Evidence;

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
    public RealmIdentity getRealmIdentity(final String name, final Principal principal, final Evidence evidence) throws RealmUnavailableException {
        if (name == null) {
            return RealmIdentity.NON_EXISTENT;
        }
        return new KeyStoreRealmIdentity(name);
    }

    @Override
    public SupportLevel getCredentialAcquireSupport(final Class<? extends Credential> credentialType, final String algorithmName) throws RealmUnavailableException {
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
        public SupportLevel getCredentialAcquireSupport(final Class<? extends Credential> credentialType, final String algorithmName) throws RealmUnavailableException {
            final KeyStore.Entry entry = getEntry(name);
            if (entry == null) {
                return SupportLevel.UNSUPPORTED;
            }
            final Credential credential = Credential.fromKeyStoreEntry(entry);
            if (credentialType.isInstance(credential)) {
                if (algorithmName == null || credential instanceof AlgorithmCredential && algorithmName.equals(((AlgorithmCredential) credential).getAlgorithm())) {
                    return SupportLevel.SUPPORTED;
                }
            }
            return SupportLevel.UNSUPPORTED;
        }

        @Override
        public <C extends Credential> C getCredential(final Class<C> credentialType, final String algorithmName) throws RealmUnavailableException {
            Assert.checkNotNullParam("credentialType", credentialType);
            final KeyStore.Entry entry = getEntry(name);
            if (entry == null) return null;
            final Credential credential = Credential.fromKeyStoreEntry(entry);
            if (credentialType.isInstance(credential)) {
                if (algorithmName == null || credential instanceof AlgorithmCredential && algorithmName.equals(((AlgorithmCredential) credential).getAlgorithm())) {
                    return credentialType.cast(credential);
                }
            }
            return null;
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
                return false;
            }
            final Credential credential = Credential.fromKeyStoreEntry(entry);
            return credential != null && credential.canVerify(evidence) && credential.verify(evidence);
        }

        public boolean exists() throws RealmUnavailableException {
            return getEntry(name) != null;
        }

        public boolean createdBySecurityRealm(final SecurityRealm securityRealm) {
            return KeyStoreBackedSecurityRealm.this == securityRealm;
        }
    }
}
