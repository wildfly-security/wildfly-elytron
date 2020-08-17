/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2015 Red Hat, Inc., and individual contributors
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

import java.security.Principal;
import java.security.spec.AlgorithmParameterSpec;
import java.util.function.Function;

import org.wildfly.security.auth.SupportLevel;
import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.auth.server.event.RealmAuthenticationEvent;
import org.wildfly.security.auth.server.event.RealmAuthorizationEvent;
import org.wildfly.security.auth.server.event.RealmEvent;
import org.wildfly.security.authz.AggregateAttributes;
import org.wildfly.security.authz.Attributes;
import org.wildfly.security.authz.AuthorizationIdentity;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.evidence.Evidence;

/**
 * A realm which directs authentication to one realm and authorization to another.  The authentication realm need
 * not provide any authorization information.  Likewise the authorization realm need not provide any authentication
 * credential acquisition or verification capabilities.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class AggregateSecurityRealm implements SecurityRealm {
    private final SecurityRealm authenticationRealm;
    private final SecurityRealm[] authorizationRealms;
    private final Function<Principal, Principal> principalTransformer;

    /**
     * Construct a new instance.
     *
     * @param authenticationRealm the realm to use for authentication
     * @param authorizationRealm the realm to use for authorization
     */
    public AggregateSecurityRealm(final SecurityRealm authenticationRealm, final SecurityRealm authorizationRealm) {
        this.authenticationRealm = authenticationRealm;
        this.authorizationRealms = new SecurityRealm[] { authorizationRealm };
        this.principalTransformer = null;
    }

    public AggregateSecurityRealm(final SecurityRealm authenticationRealm, final SecurityRealm... authorizationRealms) {
        this.authenticationRealm = authenticationRealm;
        this.authorizationRealms = authorizationRealms;
        this.principalTransformer = null;

    }
    public AggregateSecurityRealm(final SecurityRealm authenticationRealm, Function<Principal, Principal> principalTransformer, final SecurityRealm... authorizationRealms) {
        this.authenticationRealm = authenticationRealm;
        this.authorizationRealms = authorizationRealms;
        this.principalTransformer = principalTransformer;
    }

    public RealmIdentity getRealmIdentity(final Evidence evidence) throws RealmUnavailableException {
        boolean ok = false;
        final RealmIdentity authenticationIdentity = authenticationRealm.getRealmIdentity(evidence);
        final RealmIdentity[] authorizationIdentities = new RealmIdentity[authorizationRealms.length];
        try {
            for (int i = 0; i < authorizationIdentities.length; i++) {
                SecurityRealm authorizationRealm = authorizationRealms[i];
                authorizationIdentities[i] = (authorizationRealm == authenticationRealm) ? authenticationIdentity
                        : getAuthorizationIdentity(authorizationRealm, evidence, principalTransformer, authenticationIdentity);
            }

            final Identity identity = new Identity(authenticationIdentity, authorizationIdentities);
            ok = true;
            return identity;
        } finally {
            if (!ok) {
                authenticationIdentity.dispose();
                for (RealmIdentity current : authorizationIdentities) {
                    if (current != null)
                        current.dispose();
                }
            }
        }
    }

    public RealmIdentity getRealmIdentity(final Principal principal) throws RealmUnavailableException {
        boolean ok = false;
        final RealmIdentity authenticationIdentity = authenticationRealm.getRealmIdentity(principal);

        Principal authorizationPrincipal = principal;
        if (principalTransformer != null) {
            authorizationPrincipal = principalTransformer.apply(authorizationPrincipal);
            if (authorizationPrincipal == null) throw ElytronMessages.log.transformedPrincipalCannotBeNull();
        }

        final RealmIdentity[] authorizationIdentities = new RealmIdentity[authorizationRealms.length];
        try {
            for (int i = 0; i < authorizationIdentities.length; i++) {
                SecurityRealm authorizationRealm = authorizationRealms[i];
                authorizationIdentities[i] = (authorizationRealm == authenticationRealm) && (principalTransformer == null) ? authenticationIdentity : authorizationRealm.getRealmIdentity(authorizationPrincipal);
            }

            final Identity identity = new Identity(authenticationIdentity, authorizationIdentities);
            ok = true;
            return identity;
        } finally {
            if (!ok) {
                authenticationIdentity.dispose();
                for (RealmIdentity current : authorizationIdentities) {
                    if (current != null)
                        current.dispose();
                }
            }
        }
    }

    @Override
    public SupportLevel getCredentialAcquireSupport(final Class<? extends Credential> credentialType, final String algorithmName, final AlgorithmParameterSpec parameterSpec) throws RealmUnavailableException {
        return authenticationRealm.getCredentialAcquireSupport(credentialType, algorithmName, parameterSpec);
    }

    @Override
    public SupportLevel getEvidenceVerifySupport(final Class<? extends Evidence> evidenceType, final String algorithmName) throws RealmUnavailableException {
        return authenticationRealm.getEvidenceVerifySupport(evidenceType, algorithmName);
    }

    private RealmIdentity getAuthorizationIdentity(SecurityRealm authorizationRealm, Evidence evidence, Function<Principal, Principal> principalTransformer,
                                                   RealmIdentity authenticationIdentity) throws RealmUnavailableException {
        if (principalTransformer == null) {
            if (evidence.getPrincipal() == null) {
                return authorizationRealm.getRealmIdentity(authenticationIdentity.getRealmIdentityPrincipal());
            } else {
                return authorizationRealm.getRealmIdentity(evidence);
            }
        } else {
            if (evidence.getPrincipal() == null) {
                Principal authorizationPrincipal = authenticationIdentity.getRealmIdentityPrincipal();
                authorizationPrincipal = principalTransformer.apply(authorizationPrincipal);
                if (authorizationPrincipal == null) throw ElytronMessages.log.transformedPrincipalCannotBeNull();
                return authorizationRealm.getRealmIdentity(authorizationPrincipal);
            } else {
                return authorizationRealm.getRealmIdentity(evidence, principalTransformer);
            }
        }
    }

    public void handleRealmEvent(final RealmEvent event) {
        if (event instanceof RealmAuthenticationEvent) {
            authenticationRealm.handleRealmEvent(event);
        } else if (event instanceof RealmAuthorizationEvent) {
            for (SecurityRealm current : authorizationRealms) {
                SecurityRealm.safeHandleRealmEvent(current, event);
            }
        } else {
            // use safe wrapper to ensure both are called
            SecurityRealm.safeHandleRealmEvent(authenticationRealm, event);
            for (SecurityRealm current : authorizationRealms) {
                SecurityRealm.safeHandleRealmEvent(current, event);
            }
        }
    }

    static final class Identity implements RealmIdentity {

        private final RealmIdentity authenticationIdentity;
        private final RealmIdentity[] authorizationIdentities;

        Identity(final RealmIdentity authenticationIdentity, final RealmIdentity[] authorizationIdentities) {
            this.authenticationIdentity = authenticationIdentity;
            this.authorizationIdentities = authorizationIdentities;
        }

        @Override
        public Principal getRealmIdentityPrincipal() {
            return authenticationIdentity.getRealmIdentityPrincipal();
        }

        @Override
        public SupportLevel getCredentialAcquireSupport(final Class<? extends Credential> credentialType, final String algorithmName, final AlgorithmParameterSpec parameterSpec) throws RealmUnavailableException {
            return authenticationIdentity.getCredentialAcquireSupport(credentialType, algorithmName, parameterSpec);
        }

        @Override
        public SupportLevel getEvidenceVerifySupport(final Class<? extends Evidence> evidenceType, final String algorithmName) throws RealmUnavailableException {
            return authenticationIdentity.getEvidenceVerifySupport(evidenceType, algorithmName);
        }

        @Override
        public <C extends Credential> C getCredential(final Class<C> credentialType, final String algorithmName, final AlgorithmParameterSpec parameterSpec) throws RealmUnavailableException {
            return authenticationIdentity.getCredential(credentialType, algorithmName, parameterSpec);
        }

        @Override
        public <C extends Credential> C getCredential(final Class<C> credentialType, final String algorithmName) throws RealmUnavailableException {
            return authenticationIdentity.getCredential(credentialType, algorithmName);
        }

        @Override
        public <C extends Credential> C getCredential(final Class<C> credentialType) throws RealmUnavailableException {
            return authenticationIdentity.getCredential(credentialType);
        }

        @Override
        public boolean verifyEvidence(final Evidence evidence) throws RealmUnavailableException {
            return authenticationIdentity.verifyEvidence(evidence);
        }

        public boolean exists() throws RealmUnavailableException {
            return authenticationIdentity.exists();
        }

        public AuthorizationIdentity getAuthorizationIdentity() throws RealmUnavailableException {
            if (authorizationIdentities.length == 1) {
                return authorizationIdentities[0].getAuthorizationIdentity();
            }

            final AuthorizationIdentity[] authorizationIdentities = new AuthorizationIdentity[this.authorizationIdentities.length];
            for (int i = 0; i < authorizationIdentities.length; i++) {
                authorizationIdentities[i] = this.authorizationIdentities[i].getAuthorizationIdentity();
            }

            // Use a Supplier here so we only load and aggregate the attributes if they are actually used.
            return AuthorizationIdentity.basicIdentity(() -> combineAttributes(authorizationIdentities), "Aggregated");
        }

        private Attributes combineAttributes(AuthorizationIdentity[] authorizationIdentities) {
            Attributes[] attributes = new Attributes[authorizationIdentities.length];
            for (int i = 0; i < attributes.length; i++) {
                attributes[i] = authorizationIdentities[i].getAttributes();
            }

            return AggregateAttributes.aggregateOf(attributes);
        }

        public void dispose() {
            authenticationIdentity.dispose();
            for (RealmIdentity current : authorizationIdentities) {
                current.dispose();
            }
        }
    }

}
