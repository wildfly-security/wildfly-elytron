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

import static org.wildfly.security.http.oidc.Oidc.DEFAULT_TOKEN_SIGNATURE_ALGORITHM;

import java.util.Map;
import java.util.TreeMap;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

/**
 * Configuration for Java based adapters
 *
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @author <a href="mailto:brad.culley@spartasystems.com">Brad Culley</a>
 * @author <a href="mailto:john.ament@spartasystems.com">John D. Ament</a>
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
@JsonPropertyOrder({"realm", "realm-public-key", "auth-server-url", "ssl-required",
        "resource", "public-client", "credentials",
        "use-resource-role-mappings", "use-realm-role-mappings",
        "enable-cors", "cors-max-age", "cors-allowed-methods", "cors-exposed-headers",
        "expose-token", "bearer-only", "autodetect-bearer-only",
        "connection-pool-size",
        "allow-any-hostname", "disable-trust-manager", "truststore", "truststore-password",
        "client-keystore", "client-keystore-password", "client-key-password",
        "always-refresh-token",
        "register-node-at-startup", "register-node-period", "token-store", "adapter-state-cookie-path", "principal-attribute",
        "proxy-url", "turn-off-change-session-id-on-login", "token-minimum-time-to-live",
        "min-time-between-jwks-requests", "public-key-cache-ttl",
        "ignore-oauth-query-parameter", "verify-token-audience", "token-signature-algorithm", "scope"
})
public class OidcJsonConfiguration {

    @JsonProperty("allow-any-hostname")
    protected boolean allowAnyHostname;
    @JsonProperty("disable-trust-manager")
    protected boolean disableTrustManager;
    @JsonProperty("truststore")
    protected String truststore;
    @JsonProperty("truststore-password")
    protected String truststorePassword;
    @JsonProperty("client-keystore")
    protected String clientKeystore;
    @JsonProperty("client-keystore-password")
    protected String clientKeystorePassword;
    @JsonProperty("client-key-password")
    protected String clientKeyPassword;
    @JsonProperty("connection-pool-size")
    protected int connectionPoolSize = 20;
    @JsonProperty("always-refresh-token")
    protected boolean alwaysRefreshToken = false;
    @JsonProperty("register-node-at-startup")
    protected boolean registerNodeAtStartup = false;
    @JsonProperty("register-node-period")
    protected int registerNodePeriod = -1;
    @JsonProperty("token-store")
    protected String tokenStore;
    @JsonProperty("adapter-state-cookie-path")
    protected String tokenCookiePath;
    @JsonProperty("principal-attribute")
    protected String principalAttribute;
    @JsonProperty("turn-off-change-session-id-on-login")
    protected Boolean turnOffChangeSessionIdOnLogin;
    @JsonProperty("token-minimum-time-to-live")
    protected int tokenMinimumTimeToLive = 0;
    @JsonProperty("min-time-between-jwks-requests")
    protected int minTimeBetweenJwksRequests = 10;
    @JsonProperty("public-key-cache-ttl")
    protected int publicKeyCacheTtl = 86400; // 1 day
    // https://tools.ietf.org/html/rfc7636
    @JsonProperty("enable-pkce")
    protected boolean pkce = false;
    @JsonProperty("ignore-oauth-query-parameter")
    protected boolean ignoreOAuthQueryParameter = false;
    @JsonProperty("verify-token-audience")
    protected boolean verifyTokenAudience = false;
    @JsonProperty("confidential-port")
    protected int confidentialPort;
    @JsonProperty("resource")
    protected String resource;
    @JsonProperty("use-resource-role-mappings")
    protected boolean useResourceRoleMappings;
    @JsonProperty("use-realm-role-mappings")
    protected boolean useRealmRoleMappings = true;
    @JsonProperty("enable-cors")
    protected boolean cors;
    @JsonProperty("cors-max-age")
    protected int corsMaxAge = -1;
    @JsonProperty("cors-allowed-headers")
    protected String corsAllowedHeaders;
    @JsonProperty("cors-allowed-methods")
    protected String corsAllowedMethods;
    @JsonProperty("cors-exposed-headers")
    protected String corsExposedHeaders;
    @JsonProperty("expose-token")
    protected boolean exposeToken;
    @JsonProperty("bearer-only")
    protected boolean bearerOnly;
    @JsonProperty("autodetect-bearer-only")
    protected boolean autodetectBearerOnly;
    @JsonProperty("enable-basic-auth")
    protected boolean enableBasicAuth;
    @JsonProperty("public-client")
    protected boolean publicClient;
    @JsonProperty("credentials")
    protected Map<String, Object> credentials = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
    @JsonProperty("redirect-rewrite-rules")
    protected Map<String, String> redirectRewriteRules;
    @JsonProperty("realm")
    protected String realm;
    @JsonProperty("realm-public-key")
    protected String realmKey;
    @JsonProperty("auth-server-url")
    protected String authServerUrl;
    @JsonProperty("ssl-required")
    protected String sslRequired;
    @JsonProperty("provider-url")
    protected String providerUrl;
    @JsonProperty("client-id")
    protected String clientId;
    @JsonProperty("token-signature-algorithm")
    protected String tokenSignatureAlgorithm = DEFAULT_TOKEN_SIGNATURE_ALGORITHM;

    @JsonProperty("scope")
    protected String scope;

    /**
     * The Proxy url to use for requests to the auth-server, configurable via the adapter config property {@code proxy-url}.
     */
    @JsonProperty("proxy-url")
    protected String proxyUrl;

    public boolean isAllowAnyHostname() {
        return allowAnyHostname;
    }

    public void setAllowAnyHostname(boolean allowAnyHostname) {
        this.allowAnyHostname = allowAnyHostname;
    }

    public boolean isDisableTrustManager() {
        return disableTrustManager;
    }

    public void setDisableTrustManager(boolean disableTrustManager) {
        this.disableTrustManager = disableTrustManager;
    }

    public String getTruststore() {
        return truststore;
    }

    public void setTruststore(String truststore) {
        this.truststore = truststore;
    }

    public String getTruststorePassword() {
        return truststorePassword;
    }

    public void setTruststorePassword(String truststorePassword) {
        this.truststorePassword = truststorePassword;
    }

    public String getClientKeystore() {
        return clientKeystore;
    }

    public void setClientKeystore(String clientKeystore) {
        this.clientKeystore = clientKeystore;
    }

    public String getClientKeystorePassword() {
        return clientKeystorePassword;
    }

    public void setClientKeystorePassword(String clientKeystorePassword) {
        this.clientKeystorePassword = clientKeystorePassword;
    }

    public String getClientKeyPassword() {
        return clientKeyPassword;
    }

    public void setClientKeyPassword(String clientKeyPassword) {
        this.clientKeyPassword = clientKeyPassword;
    }

    public int getConnectionPoolSize() {
        return connectionPoolSize;
    }

    public void setConnectionPoolSize(int connectionPoolSize) {
        this.connectionPoolSize = connectionPoolSize;
    }

    public boolean isAlwaysRefreshToken() {
        return alwaysRefreshToken;
    }

    public void setAlwaysRefreshToken(boolean alwaysRefreshToken) {
        this.alwaysRefreshToken = alwaysRefreshToken;
    }

    public boolean isRegisterNodeAtStartup() {
        return registerNodeAtStartup;
    }

    public void setRegisterNodeAtStartup(boolean registerNodeAtStartup) {
        this.registerNodeAtStartup = registerNodeAtStartup;
    }

    public int getRegisterNodePeriod() {
        return registerNodePeriod;
    }

    public void setRegisterNodePeriod(int registerNodePeriod) {
        this.registerNodePeriod = registerNodePeriod;
    }

    public String getTokenStore() {
        return tokenStore;
    }

    public void setTokenStore(String tokenStore) {
        this.tokenStore = tokenStore;
    }

    public String getTokenCookiePath() {
        return tokenCookiePath;
    }

    public void setTokenCookiePath(String tokenCookiePath) {
        this.tokenCookiePath = tokenCookiePath;
    }

    public String getPrincipalAttribute() {
        return principalAttribute;
    }

    public void setPrincipalAttribute(String principalAttribute) {
        this.principalAttribute = principalAttribute;
    }

    public Boolean getTurnOffChangeSessionIdOnLogin() {
        return turnOffChangeSessionIdOnLogin;
    }

    public void setTurnOffChangeSessionIdOnLogin(Boolean turnOffChangeSessionIdOnLogin) {
        this.turnOffChangeSessionIdOnLogin = turnOffChangeSessionIdOnLogin;
    }

    public String getProxyUrl() {
        return proxyUrl;
    }

    public void setProxyUrl(String proxyUrl) {
        this.proxyUrl = proxyUrl;
    }

    public int getTokenMinimumTimeToLive() {
        return tokenMinimumTimeToLive;
    }

    public void setTokenMinimumTimeToLive(final int tokenMinimumTimeToLive) {
        this.tokenMinimumTimeToLive = tokenMinimumTimeToLive;
    }

    public int getMinTimeBetweenJwksRequests() {
        return minTimeBetweenJwksRequests;
    }

    public void setMinTimeBetweenJwksRequests(int minTimeBetweenJwksRequests) {
        this.minTimeBetweenJwksRequests = minTimeBetweenJwksRequests;
    }

    public int getPublicKeyCacheTtl() {
        return publicKeyCacheTtl;
    }

    public void setPublicKeyCacheTtl(int publicKeyCacheTtl) {
        this.publicKeyCacheTtl = publicKeyCacheTtl;
    }

    // https://tools.ietf.org/html/rfc7636
    public boolean isPkce() {
        return pkce;
    }

    public void setPkce(boolean pkce) {
        this.pkce = pkce;
    }

    public boolean isIgnoreOAuthQueryParameter() {
        return ignoreOAuthQueryParameter;
    }

    public void setIgnoreOAuthQueryParameter(boolean ignoreOAuthQueryParameter) {
        this.ignoreOAuthQueryParameter = ignoreOAuthQueryParameter;
    }

    public boolean isVerifyTokenAudience() {
        return verifyTokenAudience;
    }

    public void setVerifyTokenAudience(boolean verifyTokenAudience) {
        this.verifyTokenAudience = verifyTokenAudience;
    }

    public String getSslRequired() {
        return sslRequired;
    }

    public void setSslRequired(String sslRequired) {
        this.sslRequired = sslRequired;
    }

    public String getRealm() {
        return realm;
    }

    public void setRealm(String realm) {
        this.realm = realm;
    }

    public String getRealmKey() {
        return realmKey;
    }

    public void setRealmKey(String realmKey) {
        this.realmKey = realmKey;
    }

    public String getAuthServerUrl() {
        return authServerUrl;
    }

    public void setAuthServerUrl(String authServerUrl) {
        this.authServerUrl = authServerUrl;
    }

    public String getProviderUrl() {
        return providerUrl;
    }

    public void setProviderUrl(String providerUrl) {
        this.providerUrl = providerUrl;
    }

    public int getConfidentialPort() {
        return confidentialPort;
    }

    public void setConfidentialPort(int confidentialPort) {
        this.confidentialPort = confidentialPort;
    }

    public String getResource() {
        return resource;
    }

    public void setResource(String resource) {
        this.resource = resource;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getResourceName() {
        return resource != null ? resource : clientId;
    }

    public boolean isUseResourceRoleMappings() {
        return useResourceRoleMappings;
    }

    public void setUseResourceRoleMappings(boolean useResourceRoleMappings) {
        this.useResourceRoleMappings = useResourceRoleMappings;
    }

    public boolean isUseRealmRoleMappings() {
        return useRealmRoleMappings;
    }

    public void setUseRealmRoleMappings(boolean useRealmRoleMappings) {
        this.useRealmRoleMappings = useRealmRoleMappings;
    }

    public boolean isCors() {
        return cors;
    }

    public void setCors(boolean cors) {
        this.cors = cors;
    }

    public int getCorsMaxAge() {
        return corsMaxAge;
    }

    public void setCorsMaxAge(int corsMaxAge) {
        this.corsMaxAge = corsMaxAge;
    }

    public String getCorsAllowedHeaders() {
        return corsAllowedHeaders;
    }

    public void setCorsAllowedHeaders(String corsAllowedHeaders) {
        this.corsAllowedHeaders = corsAllowedHeaders;
    }

    public String getCorsAllowedMethods() {
        return corsAllowedMethods;
    }

    public void setCorsAllowedMethods(String corsAllowedMethods) {
        this.corsAllowedMethods = corsAllowedMethods;
    }

    public String getCorsExposedHeaders() {
        return corsExposedHeaders;
    }

    public void setCorsExposedHeaders(String corsExposedHeaders) {
        this.corsExposedHeaders = corsExposedHeaders;
    }

    public boolean isExposeToken() {
        return exposeToken;
    }

    public void setExposeToken(boolean exposeToken) {
        this.exposeToken = exposeToken;
    }

    public boolean isBearerOnly() {
        return bearerOnly;
    }

    public void setBearerOnly(boolean bearerOnly) {
        this.bearerOnly = bearerOnly;
    }

    public boolean isAutodetectBearerOnly() {
        return autodetectBearerOnly;
    }

    public void setAutodetectBearerOnly(boolean autodetectBearerOnly) {
        this.autodetectBearerOnly = autodetectBearerOnly;
    }

    public boolean isEnableBasicAuth() {
        return enableBasicAuth;
    }

    public void setEnableBasicAuth(boolean enableBasicAuth) {
        this.enableBasicAuth = enableBasicAuth;
    }

    public Map<String, Object> getCredentials() {
        return credentials;
    }

    public void setCredentials(Map<String, Object> credentials) {
        this.credentials = credentials;
    }

    public boolean isPublicClient() {
        return publicClient;
    }

    public void setPublicClient(boolean publicClient) {
        this.publicClient = publicClient;
    }

    public Map<String, String> getRedirectRewriteRules() {
        return redirectRewriteRules;
    }

    public void setRedirectRewriteRules(Map<String, String> redirectRewriteRules) {
        this.redirectRewriteRules = redirectRewriteRules;
    }

    public String getTokenSignatureAlgorithm() {
        return tokenSignatureAlgorithm;
    }

    public void setTokenSignatureAlgorithm(String tokenSignatureAlgorithm) {
        this.tokenSignatureAlgorithm = tokenSignatureAlgorithm;
    }

    public String getScope() {
        return scope;
    }

    public void setScope(String scope) {
        this.scope = scope;
    }
}

