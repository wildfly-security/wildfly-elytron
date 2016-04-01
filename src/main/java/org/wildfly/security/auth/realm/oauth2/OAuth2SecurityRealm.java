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

package org.wildfly.security.auth.realm.oauth2;

import org.wildfly.common.Assert;
import org.wildfly.security._private.ElytronMessages;
import org.wildfly.security.auth.principal.NamePrincipal;
import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.auth.server.SupportLevel;
import org.wildfly.security.authz.Attributes;
import org.wildfly.security.authz.AuthorizationIdentity;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.evidence.BearerTokenEvidence;
import org.wildfly.security.evidence.Evidence;

import javax.json.JsonObject;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;

import static org.wildfly.security.auth.realm.oauth2.OAuth2Util.introspectAccessToken;
import static org.wildfly.security.auth.realm.oauth2.OAuth2Util.toAttributes;

import java.net.URL;
import java.security.Principal;

/**
 * An oAuth2-backed {@link SecurityRealm} based on RFC-7662 in order to verify bearer tokens from a given {@link BearerTokenEvidence}
 * against a token introspection endpoint and build identities based on the token metadata or claims.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class OAuth2SecurityRealm implements SecurityRealm {

    private final URL tokenIntrospectionUrl;
    private final String clientId;
    private final String clientSecret;
    private final String principalClaimName;
    private final SSLContext sslContext;
    private final HostnameVerifier hostnameVerifier;

    public static Builder builder() {
        return new Builder();
    }

    OAuth2SecurityRealm(Builder configuration) {
        Assert.checkNotNullParam("configuration", configuration);
        this.tokenIntrospectionUrl = Assert.checkNotNullParam("tokenIntrospectionUrl", configuration.tokenIntrospectionUrl);
        this.clientId = Assert.checkNotNullParam("clientId", configuration.clientId);
        this.clientSecret = Assert.checkNotNullParam("clientSecret", configuration.clientSecret);

        if (configuration.principalClaimName == null) {
            this.principalClaimName = "username";
        } else {
            this.principalClaimName = configuration.principalClaimName;
        }

        if (tokenIntrospectionUrl.getProtocol().equalsIgnoreCase("https")) {
            if (configuration.sslContext == null) {
                throw ElytronMessages.log.oauth2RealmSSLContextNotSpecified(tokenIntrospectionUrl);
            }

            if (configuration.hostnameVerifier == null) {
                throw ElytronMessages.log.oauth2RealmHostnameVerifierNotSpecified(tokenIntrospectionUrl);
            }
        }

        this.sslContext = configuration.sslContext;
        this.hostnameVerifier = configuration.hostnameVerifier;
    }

    @Override
    public RealmIdentity getRealmIdentity(String name, Principal principal, Evidence evidence) throws RealmUnavailableException {
        return new OAuth2RealmIdentity(evidence);
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
        private JsonObject claims;

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
                    return new NamePrincipal(getClaims().getString(principalClaimName));
                }
            } catch (Exception e) {
                throw ElytronMessages.log.oauth2RealmFailedToObtainPrincipal(e);
            }
            return null;
        }

        @Override
        public boolean verifyEvidence(Evidence evidence) throws RealmUnavailableException {
            return isValidToken(introspectToken());
        }

        @Override
        public boolean exists() throws RealmUnavailableException {
            return getClaims() != null;
        }

        @Override
        public AuthorizationIdentity getAuthorizationIdentity() throws RealmUnavailableException {
            if (exists()) {
                return new AuthorizationIdentity() {
                    private Attributes attributes;

                    @Override
                    public Attributes getAttributes() {
                        if (this.attributes == null) {
                            this.attributes = toAttributes(claims);
                        }

                        return this.attributes;
                    }
                };
            }

            return null;
        }

        public boolean createdBySecurityRealm(final SecurityRealm securityRealm) {
            return OAuth2SecurityRealm.this == securityRealm;
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

        private JsonObject getClaims() throws RealmUnavailableException {
            if (this.claims == null) {
                JsonObject claims = introspectToken();

                if (isValidToken(claims)) {
                    this.claims = claims;
                }
            }

            return this.claims;
        }

        private boolean isValidToken(JsonObject claims) {
            return claims != null && claims.getBoolean("active", false);
        }

        private JsonObject introspectToken() throws RealmUnavailableException {
            if (this.evidence != null) {
                try {
                    return introspectAccessToken(tokenIntrospectionUrl,
                            clientId, clientSecret, evidence.getToken(), sslContext, hostnameVerifier);
                } catch (Exception e) {
                    throw ElytronMessages.log.oauth2RealmTokenIntrospectionFailed(e);
                }
            }

            return null;
        }
    }

    public static class Builder {

        private String clientId;
        private String clientSecret;
        private URL tokenIntrospectionUrl;
        private String principalClaimName = "username";
        private SSLContext sslContext;
        private HostnameVerifier hostnameVerifier;

        /**
         * Construct a new instance.
         */
        private Builder() {
        }

        /**
         * An {@link URL} pointing to a RFC-7662 OAuth2 Token Introspection compatible endpoint.
         *
         * @param url the token introspection endpoint
         * @return this instance
         */
        public Builder tokenIntrospectionUrl(URL url) {
            this.tokenIntrospectionUrl = url;
            return this;
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
         * <p>The identifier of a client registered within the OAuth2 Authorization Server that will be used to authenticate this server
         * in order to validate bearer tokens arriving to this server.
         *
         * <p>Please note that the client will be usually a confidential client with both an identifier and secret configured in order to
         * authenticate against the token introspection endpoint. In this case, the endpoint must support HTTP BASIC authentication using
         * the client credentials (both id and secret).
         *
         * @param clientId the identifier of a client within the OAUth2 Authorization Server
         * @return this instance
         */
        public Builder clientId(String clientId) {
            this.clientId = clientId;
            return this;
        }

        /**
         * The secret of the client identified by the given {@link #clientId}.
         *
         * @param clientSecret the secret of the client
         * @return this instance
         */
        public Builder clientSecret(String clientSecret) {
            this.clientSecret = clientSecret;
            return this;
        }

        /**
         * <p>A predefined {@link SSLContext} that will be used to connect to the token introspection endpoint when using SSL/TLS. This configuration is mandatory
         * if the given token introspection url is using SSL/TLS.
         *
         * @param sslContext the SSL context
         * @return this instance
         */
        public Builder useSslContext(SSLContext sslContext) {
            this.sslContext = sslContext;
            return this;
        }

        /**
         * A {@link HostnameVerifier} that will be used to validate the hostname when using SSL/TLS. This configuration is mandatory
         * if the given token introspection url is using SSL/TLS.
         *
         * @param hostnameVerifier the hostname verifier
         * @return this instance
         */
        public Builder useSslHostnameVerifier(HostnameVerifier hostnameVerifier) {
            this.hostnameVerifier = hostnameVerifier;
            return this;
        }

        /**
         * Creates a {@link OAuth2SecurityRealm} instance with all the given configuration.
         *
         * @return a new {@link OAuth2SecurityRealm} instance with all the given configuration
         */
        public OAuth2SecurityRealm build() {
            return new OAuth2SecurityRealm(this);
        }
    }
}
