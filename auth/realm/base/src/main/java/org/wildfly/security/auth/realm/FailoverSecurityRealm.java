/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2019 Red Hat, Inc., and individual contributors
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

import static org.wildfly.security.auth.realm.ElytronMessages.log;

import org.wildfly.security.auth.SupportLevel;
import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.authz.Attributes;
import org.wildfly.security.authz.AuthorizationIdentity;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.evidence.Evidence;

import java.security.Principal;
import java.security.spec.AlgorithmParameterSpec;
import java.util.function.Consumer;
import java.util.function.Function;

/**
 * A realm which wraps one realm and fails over to another in case the first is unavailable.
 *
 * @author <a href="mailto:mmazanek@redhat.com">Martin Mazanek</a>
 */
public class FailoverSecurityRealm implements SecurityRealm {
    protected final SecurityRealm delegateRealm;
    protected final SecurityRealm failoverRealm;
    protected final Consumer<RealmUnavailableException> failoverCallback;

    /**
     * Construct a new instance.
     *
     * @param delegateRealm the wrapped realm
     * @param failoverRealm the realm to use in case delegateRealm is unavailable
     * @param failoverCallback callback function that gets called in case delegateRealm is unavailable
     */
    public FailoverSecurityRealm(final SecurityRealm delegateRealm, final SecurityRealm failoverRealm, final Consumer<RealmUnavailableException> failoverCallback) {
        this.delegateRealm = delegateRealm;
        this.failoverRealm = failoverRealm;
        this.failoverCallback = failoverCallback;
    }

    @Override
    public RealmIdentity getRealmIdentity(final Evidence evidence) throws RealmUnavailableException {
        try {
            return createFailoverIdentity(delegateRealm.getRealmIdentity(evidence), evidence);
        } catch (RealmUnavailableException e) {
            log.realmFailover(e);
            if (failoverCallback != null) {
                failoverCallback.accept(e);
            }
            return failoverRealm.getRealmIdentity(evidence);
        }
    }

    @Override
    public RealmIdentity getRealmIdentity(final Principal principal) throws RealmUnavailableException {
        try {
            return createFailoverIdentity(delegateRealm.getRealmIdentity(principal), principal);
        } catch (RealmUnavailableException e) {
            log.realmFailover(e);
            if (failoverCallback != null) {
                failoverCallback.accept(e);
            }
            return failoverRealm.getRealmIdentity(principal);
        }
    }

    @Override
    public SupportLevel getCredentialAcquireSupport(final Class<? extends Credential> credentialType, final String algorithmName, final AlgorithmParameterSpec parameterSpec) throws RealmUnavailableException {
        try {
            return delegateRealm.getCredentialAcquireSupport(credentialType, algorithmName, parameterSpec);
        } catch (RealmUnavailableException rue) {
            log.realmFailover(rue);
            if (failoverCallback != null) {
                failoverCallback.accept(rue);
            }
            return SupportLevel.POSSIBLY_SUPPORTED;
        }
    }

    @Override
    public SupportLevel getEvidenceVerifySupport(final Class<? extends Evidence> evidenceType, final String algorithmName) throws RealmUnavailableException {
        try {
            return delegateRealm.getEvidenceVerifySupport(evidenceType, algorithmName);
        } catch (RealmUnavailableException rue) {
            log.realmFailover(rue);
            if (failoverCallback != null) {
                failoverCallback.accept(rue);
            }
            return SupportLevel.POSSIBLY_SUPPORTED;
        }
    }

    protected RealmIdentity createFailoverIdentity(final RealmIdentity identity, final Evidence evidence) {
        return new FailoverRealmIdentity(identity) {
            @Override
            protected RealmIdentity getFailoverIdentity() throws RealmUnavailableException {
                return failoverRealm.getRealmIdentity(evidence);
            }
        };
    }

    protected RealmIdentity createFailoverIdentity(final RealmIdentity identity, final Principal principal) {
        return new FailoverRealmIdentity(identity) {
            @Override
            protected RealmIdentity getFailoverIdentity() throws RealmUnavailableException {
                return failoverRealm.getRealmIdentity(principal);
            }
        };
    }

    protected abstract class FailoverRealmIdentity implements RealmIdentity {
        protected RealmIdentity delegate;
        protected boolean failed = false;

        public FailoverRealmIdentity(final RealmIdentity identity) {
            this.delegate = identity;
        }

        protected abstract RealmIdentity getFailoverIdentity() throws RealmUnavailableException;

        @Override
        public SupportLevel getCredentialAcquireSupport(Class<? extends Credential> credentialType, String algorithmName, final AlgorithmParameterSpec parameterSpec) throws RealmUnavailableException {
            try {
                return delegate.getCredentialAcquireSupport(credentialType, algorithmName, parameterSpec);
            } catch (RealmUnavailableException rue) {
                return failover(rue).getCredentialAcquireSupport(credentialType, algorithmName, parameterSpec);
            }
        }

        @Override
        public <C extends Credential> C getCredential(Class<C> credentialType) throws RealmUnavailableException {
            try {
                return delegate.getCredential(credentialType);
            } catch (RealmUnavailableException rue) {
                return failover(rue).getCredential(credentialType);
            } finally {
                disableFailover();
            }
        }

        @Override
        public SupportLevel getEvidenceVerifySupport(Class<? extends Evidence> evidenceType, String algorithmName) throws RealmUnavailableException {
            try {
                return delegate.getEvidenceVerifySupport(evidenceType, algorithmName);
            } catch (RealmUnavailableException rue) {
                return failover(rue).getEvidenceVerifySupport(evidenceType, algorithmName);
            }
        }

        @Override
        public boolean verifyEvidence(Evidence evidence) throws RealmUnavailableException {
            try {
                return delegate.verifyEvidence(evidence);
            } catch (RealmUnavailableException rue) {
                return failover(rue).verifyEvidence(evidence);
            } finally {
                disableFailover();
            }
        }

        @Override
        public boolean exists() throws RealmUnavailableException {
            try {
                return delegate.exists();
            } catch (RealmUnavailableException rue) {
                return failover(rue).exists();
            } finally {
                disableFailover();
            }
        }

        @Override
        public void updateCredential(Credential credential) throws RealmUnavailableException {
            try {
                delegate.updateCredential(credential);
            } catch (RealmUnavailableException rue) {
                failover(rue).updateCredential(credential);
            } finally {
                disableFailover();
            }
        }

        @Override
        public Principal getRealmIdentityPrincipal() {
            return delegate.getRealmIdentityPrincipal();
        }

        @Override
        public <C extends Credential> C getCredential(Class<C> credentialType, String algorithmName) throws RealmUnavailableException {
            try {
                return delegate.getCredential(credentialType, algorithmName);
            } catch (RealmUnavailableException rue) {
                return failover(rue).getCredential(credentialType, algorithmName);
            } finally {
                disableFailover();
            }
        }

        @Override
        public <C extends Credential> C getCredential(final Class<C> credentialType, final String algorithmName, final AlgorithmParameterSpec parameterSpec) throws RealmUnavailableException {
            try {
                return delegate.getCredential(credentialType, algorithmName, parameterSpec);
            } catch (RealmUnavailableException rue) {
                return failover(rue).getCredential(credentialType, algorithmName, parameterSpec);
            } finally {
                disableFailover();
            }
        }

        @Override
        public <C extends Credential, R> R applyToCredential(Class<C> credentialType, Function<C, R> function) throws RealmUnavailableException {
            try {
                return delegate.applyToCredential(credentialType, function);
            } catch (RealmUnavailableException rue) {
                return failover(rue).applyToCredential(credentialType, function);
            } finally {
                disableFailover();
            }
        }

        @Override
        public <C extends Credential, R> R applyToCredential(Class<C> credentialType, String algorithmName, Function<C, R> function) throws RealmUnavailableException {
            try {
                return delegate.applyToCredential(credentialType, algorithmName, function);
            } catch (RealmUnavailableException rue) {
                return failover(rue).applyToCredential(credentialType, algorithmName, function);
            } finally {
                disableFailover();
            }
        }

        @Override
        public <C extends Credential, R> R applyToCredential(final Class<C> credentialType, final String algorithmName, final AlgorithmParameterSpec parameterSpec, final Function<C, R> function) throws RealmUnavailableException {
            try {
                return delegate.applyToCredential(credentialType, algorithmName, parameterSpec, function);
            } catch (RealmUnavailableException rue) {
                return failover(rue).applyToCredential(credentialType, algorithmName, parameterSpec, function);
            } finally {
                disableFailover();
            }
        }

        @Override
        public void dispose() {
            delegate.dispose();
        }

        @Override
        public AuthorizationIdentity getAuthorizationIdentity() throws RealmUnavailableException {
            try {
                return delegate.getAuthorizationIdentity();
            } catch (RealmUnavailableException rue) {
                return failover(rue).getAuthorizationIdentity();
            } finally {
                disableFailover();
            }
        }

        @Override
        public Attributes getAttributes() throws RealmUnavailableException {
            return delegate.getAttributes();
        }

        protected RealmIdentity failover(RealmUnavailableException rue) throws RealmUnavailableException {
            if (failed) {
                throw rue;
            }
            log.realmFailover(rue);
            if (FailoverSecurityRealm.this.failoverCallback != null) {
                FailoverSecurityRealm.this.failoverCallback.accept(rue);
            }
            failed = true;
            delegate.dispose();
            delegate = getFailoverIdentity();
            return delegate;
        }

        // Used to make sure that failover cannot happen in the middle of authentication.
        protected void disableFailover() {
            failed = true;
        }
    }
}
