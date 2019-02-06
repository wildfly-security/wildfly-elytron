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
import org.wildfly.security.auth.principal.NamePrincipal;
import org.wildfly.security.auth.realm.token._private.ElytronMessages;
import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.auth.SupportLevel;
import org.wildfly.security.authz.Attributes;
import org.wildfly.security.authz.AuthorizationIdentity;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.evidence.BearerTokenEvidence;
import org.wildfly.security.evidence.Evidence;

import java.security.Principal;
import java.security.spec.AlgorithmParameterSpec;
import java.util.function.Function;

/**
 * <p>A {@link SecurityRealm} capable of building identities based on different security token formats based on a {@link TokenValidator}.
 *
 * @see TokenValidator
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public final class TokenSecurityRealm implements SecurityRealm {

    private final TokenValidator strategy;
    private final String principalClaimName;
    /** A function that maps the set of token claims to a Principal. */
    private final Function<Attributes, Principal> claimToPrincipal;

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

        if (configuration.claimToPrincipal == null) {
            this.claimToPrincipal = this::defaultClaimToPrincipal;
        } else {
            this.claimToPrincipal = configuration.claimToPrincipal;
        }

        this.strategy = Assert.checkNotNullParam("tokenValidationStrategy", configuration.strategy);
    }

    @Override
    public RealmIdentity getRealmIdentity(final Evidence evidence) {
        return new TokenRealmIdentity(evidence);
    }

    @Override
    public SupportLevel getCredentialAcquireSupport(Class<? extends Credential> credentialType, String algorithmName, final AlgorithmParameterSpec parameterSpec) throws RealmUnavailableException {
        return SupportLevel.UNSUPPORTED;
    }

    @Override
    public SupportLevel getEvidenceVerifySupport(Class<? extends Evidence> evidenceType, String algorithmName) throws RealmUnavailableException {
        if (isBearerTokenEvidence(evidenceType)) {
            return SupportLevel.POSSIBLY_SUPPORTED;
        }

        return SupportLevel.UNSUPPORTED;
    }

    private boolean isBearerTokenEvidence(Evidence evidence) {
        return evidence != null && isBearerTokenEvidence(evidence.getClass());
    }

    private boolean isBearerTokenEvidence(Class<?> evidenceType) {
        return BearerTokenEvidence.class.equals(evidenceType);
    }

    /**
     * The default implementation of the claimToPrincipal mapping function. Takes the {@linkplain #principalClaimName} claim
     * value and wraps it in a {@linkplain NamePrincipal}.
     * @param claims - token claims
     * @return the NamePrincipal or null on failure to extract claim value
     */
    private Principal defaultClaimToPrincipal(Attributes claims) {
        Principal principal = null;
        try {
            if (!claims.containsKey(principalClaimName)) {
                throw ElytronMessages.log.tokenRealmFailedToObtainPrincipalWithClaim(principalClaimName);
            }
            String principalName = claims.getFirst(principalClaimName);
            principal = new NamePrincipal(principalName);
        } catch (Exception e) {
            throw ElytronMessages.log.tokenRealmFailedToObtainPrincipal(e);
        }
        return principal;
    }

    final class TokenRealmIdentity implements RealmIdentity {

        private final BearerTokenEvidence evidence;
        private Attributes claims;

        TokenRealmIdentity(Evidence evidence) {
            if (isBearerTokenEvidence(evidence)) {
                this.evidence = BearerTokenEvidence.class.cast(evidence);
            } else {
                this.evidence = null;
            }
        }
        @Override
        public Principal getRealmIdentityPrincipal() {
            Principal principal = null;
            try {
                if (exists()) {
                    principal = claimToPrincipal.apply(this.claims);
                }
            } catch (Exception e) {
                throw ElytronMessages.log.tokenRealmFailedToObtainPrincipal(e);
            }
            return principal;
        }

        @Override
        public boolean verifyEvidence(Evidence evidence) throws RealmUnavailableException {
            return validateToken(evidence) != null;
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
        public SupportLevel getCredentialAcquireSupport(Class<? extends Credential> credentialType, String algorithmName, final AlgorithmParameterSpec parameterSpec) throws RealmUnavailableException {
            return SupportLevel.UNSUPPORTED;
        }

        @Override
        public <C extends Credential> C getCredential(Class<C> credentialType) throws RealmUnavailableException {
            return null;
        }

        @Override
        public SupportLevel getEvidenceVerifySupport(Class<? extends Evidence> evidenceType, String algorithmName) throws RealmUnavailableException {
            if (exists() && isBearerTokenEvidence(evidenceType)) {
                return SupportLevel.SUPPORTED;
            }

            return SupportLevel.UNSUPPORTED;
        }

        private Attributes getClaims() throws RealmUnavailableException {
            if (this.claims == null) {
                this.claims = validateToken(this.evidence);
            }

            return this.claims;
        }

        private Attributes validateToken(Evidence evidence) throws RealmUnavailableException {
            if (!isBearerTokenEvidence(evidence)) {
                return null;
            }
            BearerTokenEvidence tokenEvidence = BearerTokenEvidence.class.cast(evidence);
            try {
                return strategy.validate(tokenEvidence);
            } catch (RealmUnavailableException rue) {
                throw rue;
            } catch (Exception unknown) {
                ElytronMessages.log.debugf(unknown, "Failed to validate token evidence [%s]", tokenEvidence.getToken());
            }
            return null;
        }
    }

    public static class Builder {

        private String principalClaimName = "username";
        private Function<Attributes, Principal> claimToPrincipal;
        private TokenValidator strategy;

        /**
         * Construct a new instance.
         */
        private Builder() {
        }

        /**
         * The name of the claim that should be used to obtain the principal's name.
         *
         * @param name the name of the claim that should be used to obtain the principal's name. Defaults to <code>username</code>
         * @return this instance
         */
        public Builder principalClaimName(String name) {
            this.principalClaimName = name;
            return this;
        }

        /**
         * A function that maps the set of token claims to a Principal. If not specified, a function that takes the
         * {@linkplain #principalClaimName} claim value and wraps in in a {@linkplain NamePrincipal} is used.
         * @param func - the claim set to Principal mapping function.
         * @return the token Principal.
         */
        public Builder claimToPrincipal(Function<Attributes, Principal> func) {
            this.claimToPrincipal = func;
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
