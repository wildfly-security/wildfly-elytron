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

import org.wildfly.security.auth.server.event.RealmAuthenticationEvent;
import org.wildfly.security.auth.server.event.RealmAuthorizationEvent;
import org.wildfly.security.auth.server.event.RealmEvent;
import org.wildfly.security.authz.AuthorizationIdentity;
import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.auth.server.SupportLevel;
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
    private final SecurityRealm authorizationRealm;

    /**
     * Construct a new instance.
     *
     * @param authenticationRealm the realm to use for authentication
     * @param authorizationRealm the realm to use for authorization
     */
    public AggregateSecurityRealm(final SecurityRealm authenticationRealm, final SecurityRealm authorizationRealm) {
        this.authenticationRealm = authenticationRealm;
        this.authorizationRealm = authorizationRealm;
    }

    public RealmIdentity getRealmIdentity(final String name, final Principal principal, final Evidence evidence) throws RealmUnavailableException {
        boolean ok = false;
        final RealmIdentity authenticationIdentity = authenticationRealm.getRealmIdentity(name, principal, evidence);
        try {
            final RealmIdentity authorizationIdentity = authorizationRealm.getRealmIdentity(name, principal, evidence);
            try {
                final Identity identity = new Identity(authenticationIdentity, authorizationIdentity);
                ok = true;
                return identity;
            } finally {
                if (! ok) authorizationIdentity.dispose();
            }
        } finally {
            if (! ok) authenticationIdentity.dispose();
        }
    }

    @Override
    public SupportLevel getCredentialAcquireSupport(final Class<? extends Credential> credentialType, final String algorithmName) throws RealmUnavailableException {
        return authenticationRealm.getCredentialAcquireSupport(credentialType, algorithmName);
    }

    @Override
    public SupportLevel getEvidenceVerifySupport(final Class<? extends Evidence> evidenceType, final String algorithmName) throws RealmUnavailableException {
        return authenticationRealm.getEvidenceVerifySupport(evidenceType, algorithmName);
    }

    public void handleRealmEvent(final RealmEvent event) {
        if (event instanceof RealmAuthenticationEvent) {
            authenticationRealm.handleRealmEvent(event);
        } else if (event instanceof RealmAuthorizationEvent) {
            authorizationRealm.handleRealmEvent(event);
        } else {
            // use safe wrapper to ensure both are called
            SecurityRealm.safeHandleRealmEvent(authenticationRealm, event);
            SecurityRealm.safeHandleRealmEvent(authorizationRealm, event);
        }
    }

    static final class Identity implements RealmIdentity {

        private final RealmIdentity authenticationIdentity;
        private final RealmIdentity authorizationIdentity;

        Identity(final RealmIdentity authenticationIdentity, final RealmIdentity authorizationIdentity) {
            this.authenticationIdentity = authenticationIdentity;
            this.authorizationIdentity = authorizationIdentity;
        }

        @Override
        public SupportLevel getCredentialAcquireSupport(final Class<? extends Credential> credentialType, final String algorithmName) throws RealmUnavailableException {
            return authenticationIdentity.getCredentialAcquireSupport(credentialType, algorithmName);
        }

        @Override
        public SupportLevel getEvidenceVerifySupport(final Class<? extends Evidence> evidenceType, final String algorithmName) throws RealmUnavailableException {
            return authenticationIdentity.getEvidenceVerifySupport(evidenceType, algorithmName);
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
            return authorizationIdentity.exists() ? authorizationIdentity.getAuthorizationIdentity() : AuthorizationIdentity.EMPTY;
        }

        public void dispose() {
            authenticationIdentity.dispose();
            authorizationIdentity.dispose();
        }

        public boolean createdBySecurityRealm(final SecurityRealm securityRealm) {
            return authenticationIdentity.createdBySecurityRealm(securityRealm);
        }
    }
}
