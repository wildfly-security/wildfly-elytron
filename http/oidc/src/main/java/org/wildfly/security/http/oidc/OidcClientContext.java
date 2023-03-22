/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2020 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.wildfly.security.http.oidc;

import static org.wildfly.security.http.oidc.ElytronMessages.log;
import static org.wildfly.security.http.oidc.Oidc.SSLRequired;
import static org.wildfly.security.http.oidc.Oidc.TokenStore;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Map;

import org.apache.http.client.HttpClient;
import org.apache.http.client.utils.URIBuilder;

/**
 *
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public class OidcClientContext {

    protected OidcClientConfiguration oidcClientConfig;
    protected OidcClientConfigurationResolver oidcConfigResolver;

    public OidcClientContext() {
    }

    /**
     * Construct a new instance.
     *
     * @param oidcClientConfig the OpenID Connect client configuration to use
     */
    public OidcClientContext(OidcClientConfiguration oidcClientConfig) {
        this.oidcClientConfig = oidcClientConfig;
    }

    /**
     * Construct a new instance.
     *
     * @param oidcConfigResolver the resolver to be used to obtain the OpenID Connect client configuration
     */
    public OidcClientContext(OidcClientConfigurationResolver oidcConfigResolver) {
        this.oidcConfigResolver = oidcConfigResolver;
    }

    /**
     * For single-tenant deployments, it complements KeycloakDeployment
     * by resolving a relative Auth Server's URL based on the current request
     *
     * For multi-tenant deployments, defers the resolution of KeycloakDeployment
     * to the KeycloakConfigResolver .
     *
     * @param facade the Request/Response Façade , used to either determine
     *               the Auth Server URL (single tenant) or pass thru to the
     *               KeycloakConfigResolver.
     * @return
     */
    public OidcClientConfiguration resolveDeployment(OidcHttpFacade facade) {
        if (oidcConfigResolver != null) {
            return oidcConfigResolver.resolve(facade.getRequest());
        }

        if (oidcClientConfig == null) return null;
        if (oidcClientConfig.getAuthServerBaseUrl() == null && oidcClientConfig.getProviderUrl() == null) return oidcClientConfig;

        OidcClientConfiguration resolvedDeployment = resolveUrls(oidcClientConfig, facade);
        if (resolvedDeployment.getPublicKeyLocator() == null) {
            throw new RuntimeException("KeycloakDeployment was never initialized through appropriate SPIs");
        }
        return resolvedDeployment;
    }

    protected OidcClientConfiguration resolveUrls(OidcClientConfiguration deployment, OidcHttpFacade facade) {
        if (deployment.relativeUrls == OidcClientConfiguration.RelativeUrlsUsed.NEVER) {
            // Absolute URI are already set to everything
            return deployment;
        } else {
            OidcClientConfigurationDelegate delegate = new OidcClientConfigurationDelegate(this.oidcClientConfig);
            if (oidcClientConfig.getAuthServerBaseUrl() != null) {
                delegate.setAuthServerBaseUrl(getAuthServerBaseUrl(facade, this.oidcClientConfig.getAuthServerBaseUrl()));
            }
            if (oidcClientConfig.getProviderUrl() != null) {
                delegate.setProviderUrl(oidcClientConfig.getProviderUrl());
            }
            return delegate;
        }
    }

    /**
     * This delegate is used to store temporary, per-request metadata like request resolved URLs.
     * Ever method is delegated except URL get methods and isConfigured()
     *
     */
    protected static class OidcClientConfigurationDelegate extends OidcClientConfiguration {
        protected OidcClientConfiguration delegate;

        public OidcClientConfigurationDelegate(OidcClientConfiguration delegate) {
            this.delegate = delegate;
        }

        public void setAuthServerBaseUrl(String authServerBaseUrl) {
            this.authServerBaseUrl = authServerBaseUrl;
            resolveUrls();
        }

        public void setProviderUrl(String providerUrl) {
            this.providerUrl = providerUrl;
            resolveUrls();
        }

        @Override
        public RelativeUrlsUsed getRelativeUrls() {
            return delegate.getRelativeUrls();
        }

        @Override
        public String getTokenUrl() {
            return (this.tokenUrl != null) ? this.tokenUrl : delegate.getTokenUrl();
        }

        @Override
        public String getEndSessionEndpointUrl() {
            return (this.endSessionEndpointUrl != null) ? this.endSessionEndpointUrl : delegate.getEndSessionEndpointUrl();
        }

        @Override
        public String getAccountUrl() {
            return (this.accountUrl != null) ? this.accountUrl : delegate.getAccountUrl();
        }

        @Override
        public String getRegisterNodeUrl() {
            return (this.registerNodeUrl != null) ? this.registerNodeUrl : delegate.getRegisterNodeUrl();
        }

        @Override
        public String getUnregisterNodeUrl() {
            return (this.unregisterNodeUrl != null) ? this.unregisterNodeUrl : delegate.getUnregisterNodeUrl();
        }

        @Override
        public String getJwksUrl() {
            return (this.jwksUrl != null) ? this.jwksUrl : delegate.getJwksUrl();
        }

        @Override
        public String getResource() {
            return delegate.getResource();
        }

        @Override
        public String getClientId() {
            return delegate.getClientId();
        }

        @Override
        public String getResourceName() {
            return delegate.getResourceName();
        }

        @Override
        public String getRealm() {
            return delegate.getRealm();
        }

        @Override
        public void setRealm(String realm) {
            delegate.setRealm(realm);
        }

        @Override
        public void setPublicKeyLocator(PublicKeyLocator publicKeyLocator) {
            delegate.setPublicKeyLocator(publicKeyLocator);
        }

        @Override
        public PublicKeyLocator getPublicKeyLocator() {
            return delegate.getPublicKeyLocator();
        }

        @Override
        public void setResource(String resourceName) {
            delegate.setResource(resourceName);
        }

        @Override
        public void setClientId(String clientId) {
            delegate.setClientId(clientId);
        }

        @Override
        public boolean isBearerOnly() {
            return delegate.isBearerOnly();
        }

        @Override
        public void setBearerOnly(boolean bearerOnly) {
            delegate.setBearerOnly(bearerOnly);
        }

        @Override
        public boolean isAutodetectBearerOnly() {
            return delegate.isAutodetectBearerOnly();
        }

        @Override
        public void setAutodetectBearerOnly(boolean autodetectBearerOnly) {
            delegate.setAutodetectBearerOnly(autodetectBearerOnly);
        }

        @Override
        public boolean isEnableBasicAuth() {
            return delegate.isEnableBasicAuth();
        }

        @Override
        public void setEnableBasicAuth(boolean enableBasicAuth) {
            delegate.setEnableBasicAuth(enableBasicAuth);
        }

        @Override
        public boolean isPublicClient() {
            return delegate.isPublicClient();
        }

        @Override
        public void setPublicClient(boolean publicClient) {
            delegate.setPublicClient(publicClient);
        }

        @Override
        public Map<String, Object> getResourceCredentials() {
            return delegate.getResourceCredentials();
        }

        @Override
        public void setResourceCredentials(Map<String, Object> resourceCredentials) {
            delegate.setResourceCredentials(resourceCredentials);
        }

        @Override
        public void setClientAuthenticator(ClientCredentialsProvider clientAuthenticator) {
            delegate.setClientAuthenticator(clientAuthenticator);
        }

        @Override
        public ClientCredentialsProvider getClientAuthenticator() {
            return delegate.getClientAuthenticator();
        }

        @Override
        public HttpClient getClient() {
            return delegate.getClient();
        }

        @Override
        public void setClient(HttpClient client) {
            delegate.setClient(client);
        }

        @Override
        public String getScope() {
            return delegate.getScope();
        }

        @Override
        public void setScope(String scope) {
            delegate.setScope(scope);
        }

        @Override
        public SSLRequired getSSLRequired() {
            return delegate.getSSLRequired();
        }

        @Override
        public void setSSLRequired(SSLRequired sslRequired) {
            delegate.setSSLRequired(sslRequired);
        }

        @Override
        public int getConfidentialPort() {
            return delegate.getConfidentialPort();
        }

        @Override
        public void setConfidentialPort(int confidentialPort) {
            delegate.setConfidentialPort(confidentialPort);
        }

        @Override
        public TokenStore getTokenStore() {
            return delegate.getTokenStore();
        }

        @Override
        public void setTokenStore(TokenStore tokenStore) {
            delegate.setTokenStore(tokenStore);
        }

        @Override
        public String getOidcStateCookiePath() {
            return delegate.getOidcStateCookiePath();
        }

        @Override
        public void setOidcStateCookiePath(String oidcStateCookiePath) {
            delegate.setOidcStateCookiePath(oidcStateCookiePath);
        }

        @Override
        public String getStateCookieName() {
            return delegate.getStateCookieName();
        }

        @Override
        public void setStateCookieName(String stateCookieName) {
            delegate.setStateCookieName(stateCookieName);
        }

        @Override
        public boolean isUseResourceRoleMappings() {
            return delegate.isUseResourceRoleMappings();
        }

        @Override
        public void setUseResourceRoleMappings(boolean useResourceRoleMappings) {
            delegate.setUseResourceRoleMappings(useResourceRoleMappings);
        }

        @Override
        public boolean isUseRealmRoleMappings() {
            return delegate.isUseRealmRoleMappings();
        }

        @Override
        public void setUseRealmRoleMappings(boolean useRealmRoleMappings) {
            delegate.setUseRealmRoleMappings(useRealmRoleMappings);
        }

        @Override
        public boolean isCors() {
            return delegate.isCors();
        }

        @Override
        public void setCors(boolean cors) {
            delegate.setCors(cors);
        }

        @Override
        public int getCorsMaxAge() {
            return delegate.getCorsMaxAge();
        }

        @Override
        public void setCorsMaxAge(int corsMaxAge) {
            delegate.setCorsMaxAge(corsMaxAge);
        }

        @Override
        public String getCorsAllowedHeaders() {
            return delegate.getCorsAllowedHeaders();
        }

        @Override
        public void setNotBefore(int notBefore) {
            delegate.setNotBefore(notBefore);
        }

        @Override
        public int getNotBefore() {
            return delegate.getNotBefore();
        }

        @Override
        public void updateNotBefore(int notBefore) {
            delegate.setNotBefore(notBefore);
            getPublicKeyLocator().reset(this);
        }

        @Override
        public void setExposeToken(boolean exposeToken) {
            delegate.setExposeToken(exposeToken);
        }

        @Override
        public boolean isExposeToken() {
            return delegate.isExposeToken();
        }

        @Override
        public void setCorsAllowedMethods(String corsAllowedMethods) {
            delegate.setCorsAllowedMethods(corsAllowedMethods);
        }

        @Override
        public String getCorsAllowedMethods() {
            return delegate.getCorsAllowedMethods();
        }

        @Override
        public void setCorsAllowedHeaders(String corsAllowedHeaders) {
            delegate.setCorsAllowedHeaders(corsAllowedHeaders);
        }

        @Override
        public boolean isAlwaysRefreshToken() {
            return delegate.isAlwaysRefreshToken();
        }

        @Override
        public void setAlwaysRefreshToken(boolean alwaysRefreshToken) {
            delegate.setAlwaysRefreshToken(alwaysRefreshToken);
        }

        @Override
        public int getRegisterNodePeriod() {
            return delegate.getRegisterNodePeriod();
        }

        @Override
        public void setRegisterNodePeriod(int registerNodePeriod) {
            delegate.setRegisterNodePeriod(registerNodePeriod);
        }

        @Override
        public void setRegisterNodeAtStartup(boolean registerNodeAtStartup) {
            delegate.setRegisterNodeAtStartup(registerNodeAtStartup);
        }

        @Override
        public boolean isRegisterNodeAtStartup() {
            return delegate.isRegisterNodeAtStartup();
        }

        @Override
        public String getPrincipalAttribute() {
            return delegate.getPrincipalAttribute();
        }

        @Override
        public void setPrincipalAttribute(String principalAttribute) {
            delegate.setPrincipalAttribute(principalAttribute);
        }

        @Override
        public boolean isTurnOffChangeSessionIdOnLogin() {
            return delegate.isTurnOffChangeSessionIdOnLogin();
        }

        @Override
        public void setTurnOffChangeSessionIdOnLogin(boolean turnOffChangeSessionIdOnLogin) {
            delegate.setTurnOffChangeSessionIdOnLogin(turnOffChangeSessionIdOnLogin);
        }

        @Override
        public int getTokenMinimumTimeToLive() {
            return delegate.getTokenMinimumTimeToLive();
        }

        @Override
        public void setTokenMinimumTimeToLive(final int tokenMinimumTimeToLive) {
            delegate.setTokenMinimumTimeToLive(tokenMinimumTimeToLive);
        }

        @Override
        public void setMinTimeBetweenJwksRequests(int minTimeBetweenJwksRequests) {
            delegate.setMinTimeBetweenJwksRequests(minTimeBetweenJwksRequests);
        }

        @Override
        public int getMinTimeBetweenJwksRequests() {
            return delegate.getMinTimeBetweenJwksRequests();
        }

        @Override
        public int getPublicKeyCacheTtl() {
            return delegate.getPublicKeyCacheTtl();
        }

        @Override
        public void setPublicKeyCacheTtl(int publicKeyCacheTtl) {
            delegate.setPublicKeyCacheTtl(publicKeyCacheTtl);
        }

        @Override
        public Map<String, String> getRedirectRewriteRules() {
            return delegate.getRedirectRewriteRules();
        }

        @Override
        public boolean isVerifyTokenAudience() {
            return delegate.isVerifyTokenAudience();
        }

        @Override
        public void setVerifyTokenAudience(boolean verifyTokenAudience) {
            delegate.setVerifyTokenAudience(verifyTokenAudience);
        }

        @Override
        public String getTokenSignatureAlgorithm() {
            return delegate.getTokenSignatureAlgorithm();
        }

        @Override
        public void setTokenSignatureAlgorithm(String tokenSignatureAlgorithm) {
            delegate.setTokenSignatureAlgorithm(tokenSignatureAlgorithm);
        }
    }

    protected String getAuthServerBaseUrl(OidcHttpFacade facade, String base) {
        try {
            URIBuilder builder = new URIBuilder(base);
            URI request = URI.create(facade.getRequest().getURI());
            String scheme = request.getScheme();
            if (oidcClientConfig.getSSLRequired().isRequired(facade.getRequest().getRemoteAddr())) {
                scheme = "https";
                if (! request.getScheme().equals(scheme) && request.getPort() != -1) {
                    log.error("request scheme: " + request.getScheme() + " ssl required");
                    throw log.unableToResolveARelativeUrl();
                }
            }
            builder.setScheme(scheme);
            builder.setHost(request.getHost());
            if (request.getPort() != -1) {
                builder.setPort(request.getPort());
            }
            return builder.build().toString();
        } catch (URISyntaxException e) {
            throw log.unableToSetAuthServerUrl(e);
        }
    }
}
