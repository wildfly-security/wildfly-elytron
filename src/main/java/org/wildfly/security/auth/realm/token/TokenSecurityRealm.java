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

package org.wildfly.security.auth.realm.token;

import org.wildfly.common.Assert;
import org.wildfly.security._private.ElytronMessages;
import org.wildfly.security.auth.principal.NamePrincipal;
import org.wildfly.security.auth.server.IdentityLocator;
import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.auth.server.SupportLevel;
import org.wildfly.security.authz.Attributes;
import org.wildfly.security.authz.AuthorizationIdentity;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.evidence.BearerTokenEvidence;
import org.wildfly.security.evidence.Evidence;

import java.security.Principal;

/**
 * <p>A {@link SecurityRealm} capable of building identities based on different security token formats based on a {@link TokenValidator}.
 *
 * @see TokenValidator
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public final class TokenSecurityRealm implements SecurityRealm {

    private final TokenValidator strategy;
    private final String principalClaimName;

    /**
     * Returns a {@link Builder} instance that can be used to configure and create a {@link TokenSecurityRealm}.
     *
     * @return the {@link Builder}
     */
    public static Builder builder() {
        return new Builder();
    }

    TokenSecurityRealm(Builder configuration) {
        Assert.checkNotNullParam("configuration", configuration);

        if (configuration.principalClaimName == null) {
            this.principalClaimName = "username";
        } else {
            this.principalClaimName = configuration.principalClaimName;
        }

        this.strategy = Assert.checkNotNullParam("tokenValidationStrategy(", configuration.strategy);
    }

    @Override
    public RealmIdentity getRealmIdentity(IdentityLocator identityLocator) throws RealmUnavailableException {
        return new OAuth2RealmIdentity(identityLocator.getEvidence());
    }

    @Override
    public SupportLevel getCredentialAcquireSupport(Class<? extends Credential> credentialType, String algorithmName) throws RealmUnavailableException {
        return SupportLevel.UNSUPPORTED;
    }

    @Override
    public SupportLevel getEvidenceVerifySupport(Class<? extends Evidence> evidenceType, String algorithmName) throws RealmUnavailableException {
        if (isBearerTokenEvidence(evidenceType)) {
            return SupportLevel.POSSIBLY_SUPPORTED;
        }

        return SupportLevel.UNSUPPORTED;
    }

    private boolean isBearerTokenEvidence(Class<?> evidenceType) {
        return evidenceType != null && evidenceType.equals(BearerTokenEvidence.class);
    }

    final class OAuth2RealmIdentity implements RealmIdentity {

        private final BearerTokenEvidence evidence;
        private Attributes claims;

        OAuth2RealmIdentity(Evidence evidence) {
            if (evidence != null && isBearerTokenEvidence(evidence.getClass())) {
                this.evidence = (BearerTokenEvidence) evidence;
            } else {
                this.evidence = null;
            }
        }
        @Override
        public Principal getRealmIdentityPrincipal() {
            try {
                if (exists()) {
                    if (!this.claims.containsKey(principalClaimName)) {
                        throw ElytronMessages.log.tokenRealmFailedToObtainPrincipalWithClaim(principalClaimName);
                    }

                    return new NamePrincipal(this.claims.getFirst(principalClaimName));
                }
            } catch (Exception e) {
                throw ElytronMessages.log.tokenRealmFailedToObtainPrincipal(e);
            }

            return null;
        }

        @Override
        public boolean verifyEvidence(Evidence evidence) throws RealmUnavailableException {
            if (!isBearerTokenEvidence(evidence.getClass())) {
                return false;
            }

            return strategy.validate((BearerTokenEvidence) evidence) != null;
        }

        @Override
        public boolean exists() throws RealmUnavailableException {
            return getClaims() != null;
        }

        @Override
        public AuthorizationIdentity getAuthorizationIdentity() throws RealmUnavailableException {
            if (exists()) {
                return new AuthorizationIdentity() {
                    @Override
                    public Attributes getAttributes() {
                        return claims;
                    }
                };
            }

            return null;
        }

        @Override
        public SupportLevel getCredentialAcquireSupport(Class<? extends Credential> credentialType, String algorithmName) throws RealmUnavailableException {
            return SupportLevel.UNSUPPORTED;
        }

        @Override
        public <C extends Credential> C getCredential(Class<C> credentialType) throws RealmUnavailableException {
            return null;
        }

        @Override
        public SupportLevel getEvidenceVerifySupport(Class<? extends Evidence> evidenceType, String algorithmName) throws RealmUnavailableException {
            if (isBearerTokenEvidence(evidenceType)) {
                return SupportLevel.SUPPORTED;
            }

            return SupportLevel.UNSUPPORTED;
        }

        private Attributes getClaims() throws RealmUnavailableException {
            if (this.claims == null && this.evidence != null) {
                this.claims = strategy.validate(this.evidence);
            }

            return this.claims;
        }
    }

    public static class Builder {

        private String principalClaimName = "username";
        private TokenValidator strategy;

        /**
         * Construct a new instance.
         */
        private Builder() {
        }

        /**
         * The name of the claim returned from the token introspection endpoint that contains the principal's name.
         *
         * @param name the name of the claim containing the principal's name. Defaults to <code>username</code>
         * @return this instance
         */
        public Builder principalClaimName(String name) {
            this.principalClaimName = name;
            return this;
        }

        /**
         * Defines a {@link TokenValidator} that will be used to validate tokens.
         *
         * @return this instance
         */
        public Builder validator(TokenValidator strategy) {
            this.strategy = strategy;
            return this;
        }

        /**
         * Creates a {@link TokenSecurityRealm} instance with all the given configuration.
         *
         * @return a new {@link TokenSecurityRealm} instance with all the given configuration
         */
        public TokenSecurityRealm build() {
            return new TokenSecurityRealm(this);
        }
    }
}
