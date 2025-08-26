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

import static org.wildfly.security.http.oidc.Oidc.CONNECTION_TIMEOUT_MILLIS;
import static org.wildfly.security.http.oidc.Oidc.CONNECTION_TTL_MILLIS;
import static org.wildfly.security.http.oidc.Oidc.DEFAULT_TOKEN_SIGNATURE_ALGORITHM;
import static org.wildfly.security.http.oidc.Oidc.ADAPTER_STATE_COOKIE_PATH;
import static org.wildfly.security.http.oidc.Oidc.ALLOW_ANY_HOSTNAME;
import static org.wildfly.security.http.oidc.Oidc.ALWAYS_REFRESH_TOKEN;
import static org.wildfly.security.http.oidc.Oidc.AUTH_SERVER_URL;
import static org.wildfly.security.http.oidc.Oidc.AUTHENTICATION_REQUEST_FORMAT;
import static org.wildfly.security.http.oidc.Oidc.AUTODETECT_BEARER_ONLY;
import static org.wildfly.security.http.oidc.Oidc.BEARER_ONLY;
import static org.wildfly.security.http.oidc.Oidc.CLIENT_ID_JSON_VALUE;
import static org.wildfly.security.http.oidc.Oidc.CLIENT_KEYSTORE;
import static org.wildfly.security.http.oidc.Oidc.CLIENT_KEYSTORE_PASSWORD;
import static org.wildfly.security.http.oidc.Oidc.CLIENT_KEY_PASSWORD;
import static org.wildfly.security.http.oidc.Oidc.CONFIDENTIAL_PORT;
import static org.wildfly.security.http.oidc.Oidc.CONNECTION_POOL_SIZE;
import static org.wildfly.security.http.oidc.Oidc.CORS_ALLOWED_HEADERS;
import static org.wildfly.security.http.oidc.Oidc.CORS_ALLOWED_METHODS;
import static org.wildfly.security.http.oidc.Oidc.CORS_EXPOSED_HEADERS;
import static org.wildfly.security.http.oidc.Oidc.CORS_MAX_AGE;
import static org.wildfly.security.http.oidc.Oidc.CREDENTIALS;
import static org.wildfly.security.http.oidc.Oidc.DISABLE_TRUST_MANAGER;
import static org.wildfly.security.http.oidc.Oidc.ENABLE_BASIC_AUTH;
import static org.wildfly.security.http.oidc.Oidc.ENABLE_CORS;
import static org.wildfly.security.http.oidc.Oidc.ENABLE_PKCE;
import static org.wildfly.security.http.oidc.Oidc.EXPOSE_TOKEN;
import static org.wildfly.security.http.oidc.Oidc.IGNORE_OAUTH_QUERY_PARAMETER;
import static org.wildfly.security.http.oidc.Oidc.MIN_TIME_BETWEEN_JWKS_REQUESTS;
import static org.wildfly.security.http.oidc.Oidc.PRINCIPAL_ATTRIBUTE;
import static org.wildfly.security.http.oidc.Oidc.PROVIDER_URL;
import static org.wildfly.security.http.oidc.Oidc.PROXY_URL;
import static org.wildfly.security.http.oidc.Oidc.PUBLIC_CLIENT;
import static org.wildfly.security.http.oidc.Oidc.PUBLIC_KEY_CACHE_TTL;
import static org.wildfly.security.http.oidc.Oidc.REDIRECT_REWRITE_RULES;
import static org.wildfly.security.http.oidc.Oidc.REGISTER_NODE_AT_STARTUP;
import static org.wildfly.security.http.oidc.Oidc.REGISTER_NODE_PERIOD;
import static org.wildfly.security.http.oidc.Oidc.REALM;
import static org.wildfly.security.http.oidc.Oidc.REALM_PUBLIC_KEY;
import static org.wildfly.security.http.oidc.Oidc.RESOURCE;
import static org.wildfly.security.http.oidc.Oidc.REQUEST_OBJECT_ENCRYPTION_ALG_VALUE;
import static org.wildfly.security.http.oidc.Oidc.REQUEST_OBJECT_ENCRYPTION_ENC_VALUE;
import static org.wildfly.security.http.oidc.Oidc.REQUEST_OBJECT_SIGNING_ALGORITHM;
import static org.wildfly.security.http.oidc.Oidc.REQUEST_OBJECT_SIGNING_KEY_ALIAS;
import static org.wildfly.security.http.oidc.Oidc.REQUEST_OBJECT_SIGNING_KEY_PASSWORD;
import static org.wildfly.security.http.oidc.Oidc.REQUEST_OBJECT_SIGNING_KEYSTORE_FILE;
import static org.wildfly.security.http.oidc.Oidc.REQUEST_OBJECT_SIGNING_KEYSTORE_PASSWORD;
import static org.wildfly.security.http.oidc.Oidc.REQUEST_OBJECT_SIGNING_KEYSTORE_TYPE;
import static org.wildfly.security.http.oidc.Oidc.SCOPE;
import static org.wildfly.security.http.oidc.Oidc.SOCKET_TIMEOUT_MILLIS;
import static org.wildfly.security.http.oidc.Oidc.SSL_REQUIRED;
import static org.wildfly.security.http.oidc.Oidc.TOKEN_MINIMUM_TIME_TO_LIVE;
import static org.wildfly.security.http.oidc.Oidc.TOKEN_SIGNATURE_ALGORITHM;
import static org.wildfly.security.http.oidc.Oidc.TOKEN_STORE;
import static org.wildfly.security.http.oidc.Oidc.TRUSTSTORE;
import static org.wildfly.security.http.oidc.Oidc.TRUSTSTORE_PASSWORD;
import static org.wildfly.security.http.oidc.Oidc.TURN_OFF_CHANGE_SESSION_ID_ON_LOGIN;
import static org.wildfly.security.http.oidc.Oidc.USE_RESOURCE_ROLE_MAPPINGS;
import static org.wildfly.security.http.oidc.Oidc.USE_REALM_ROLE_MAPPINGS;
import static org.wildfly.security.http.oidc.Oidc.VERIFY_TOKEN_AUDIENCE;

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
@JsonPropertyOrder({REALM, REALM_PUBLIC_KEY, AUTH_SERVER_URL, SSL_REQUIRED,
        RESOURCE, PUBLIC_CLIENT, CREDENTIALS,
        USE_RESOURCE_ROLE_MAPPINGS, USE_REALM_ROLE_MAPPINGS,
        ENABLE_CORS, CORS_MAX_AGE, CORS_ALLOWED_METHODS, CORS_EXPOSED_HEADERS,
        EXPOSE_TOKEN, BEARER_ONLY, AUTODETECT_BEARER_ONLY, CONNECTION_POOL_SIZE,
        CONNECTION_TIMEOUT_MILLIS, CONNECTION_TTL_MILLIS, SOCKET_TIMEOUT_MILLIS,
        ALLOW_ANY_HOSTNAME, DISABLE_TRUST_MANAGER, TRUSTSTORE, TRUSTSTORE_PASSWORD,
        CLIENT_KEYSTORE, CLIENT_KEYSTORE_PASSWORD, CLIENT_KEY_PASSWORD,
        ALWAYS_REFRESH_TOKEN,
        REGISTER_NODE_AT_STARTUP, REGISTER_NODE_PERIOD, TOKEN_STORE, ADAPTER_STATE_COOKIE_PATH, PRINCIPAL_ATTRIBUTE,
        PROXY_URL, TURN_OFF_CHANGE_SESSION_ID_ON_LOGIN, TOKEN_MINIMUM_TIME_TO_LIVE,
        MIN_TIME_BETWEEN_JWKS_REQUESTS, PUBLIC_KEY_CACHE_TTL,
        IGNORE_OAUTH_QUERY_PARAMETER, VERIFY_TOKEN_AUDIENCE, TOKEN_SIGNATURE_ALGORITHM, SCOPE,
        AUTHENTICATION_REQUEST_FORMAT, REQUEST_OBJECT_SIGNING_ALGORITHM, REQUEST_OBJECT_ENCRYPTION_ALG_VALUE,
        REQUEST_OBJECT_ENCRYPTION_ENC_VALUE, REQUEST_OBJECT_SIGNING_KEYSTORE_FILE,
        REQUEST_OBJECT_SIGNING_KEYSTORE_PASSWORD,REQUEST_OBJECT_SIGNING_KEY_PASSWORD, REQUEST_OBJECT_SIGNING_KEY_ALIAS,
        REQUEST_OBJECT_SIGNING_KEYSTORE_TYPE
})
public class OidcJsonConfiguration {

    @JsonProperty(ALLOW_ANY_HOSTNAME)
    protected boolean allowAnyHostname;
    @JsonProperty(DISABLE_TRUST_MANAGER)
    protected boolean disableTrustManager;
    @JsonProperty(TRUSTSTORE)
    protected String truststore;
    @JsonProperty(TRUSTSTORE_PASSWORD)
    protected String truststorePassword;
    @JsonProperty(CLIENT_KEYSTORE)
    protected String clientKeystore;
    @JsonProperty(CLIENT_KEYSTORE_PASSWORD)
    protected String clientKeystorePassword;
    @JsonProperty(CLIENT_KEY_PASSWORD)
    protected String clientKeyPassword;
    @JsonProperty(REQUEST_OBJECT_SIGNING_KEYSTORE_FILE)
    protected String requestObjectSigningKeyStoreFile;
    @JsonProperty(REQUEST_OBJECT_SIGNING_KEYSTORE_PASSWORD)
    protected String requestObjectSigningKeyStorePassword;
    @JsonProperty(REQUEST_OBJECT_SIGNING_KEY_PASSWORD)
    protected String requestObjectSigningKeyPassword;
    @JsonProperty(REQUEST_OBJECT_SIGNING_KEY_ALIAS)
    protected String requestObjectSigningKeyAlias;
    @JsonProperty(REQUEST_OBJECT_SIGNING_KEYSTORE_TYPE)
    protected String requestObjectSigningKeyStoreType;
    @JsonProperty(CONNECTION_POOL_SIZE)
    protected int connectionPoolSize = 20;
    @JsonProperty(CONNECTION_TIMEOUT_MILLIS)
    protected int connectionTimeoutMillis = -1;
    @JsonProperty(CONNECTION_TTL_MILLIS)
    protected int connectionTtlMillis = -1;
    @JsonProperty(SOCKET_TIMEOUT_MILLIS)
    protected int socketTimeoutMillis = -1;
    @JsonProperty(ALWAYS_REFRESH_TOKEN)
    protected boolean alwaysRefreshToken = false;
    @JsonProperty(REGISTER_NODE_AT_STARTUP)
    protected boolean registerNodeAtStartup = false;
    @JsonProperty(REGISTER_NODE_PERIOD)
    protected int registerNodePeriod = -1;
    @JsonProperty(TOKEN_STORE)
    protected String tokenStore;
    @JsonProperty(ADAPTER_STATE_COOKIE_PATH)
    protected String tokenCookiePath;
    @JsonProperty(PRINCIPAL_ATTRIBUTE)
    protected String principalAttribute;
    @JsonProperty(TURN_OFF_CHANGE_SESSION_ID_ON_LOGIN)
    protected Boolean turnOffChangeSessionIdOnLogin;
    @JsonProperty(TOKEN_MINIMUM_TIME_TO_LIVE)
    protected int tokenMinimumTimeToLive = 0;
    @JsonProperty(MIN_TIME_BETWEEN_JWKS_REQUESTS)
    protected int minTimeBetweenJwksRequests = 10;
    @JsonProperty(PUBLIC_KEY_CACHE_TTL)
    protected int publicKeyCacheTtl = 86400; // 1 day
    // https://tools.ietf.org/html/rfc7636
    @JsonProperty(ENABLE_PKCE)
    protected boolean pkce = false;
    @JsonProperty(IGNORE_OAUTH_QUERY_PARAMETER)
    protected boolean ignoreOAuthQueryParameter = false;
    @JsonProperty(VERIFY_TOKEN_AUDIENCE)
    protected boolean verifyTokenAudience = false;
    @JsonProperty(CONFIDENTIAL_PORT)
    protected int confidentialPort;
    @JsonProperty(RESOURCE)
    protected String resource;
    @JsonProperty(USE_RESOURCE_ROLE_MAPPINGS)
    protected boolean useResourceRoleMappings;
    @JsonProperty(USE_REALM_ROLE_MAPPINGS)
    protected boolean useRealmRoleMappings = true;
    @JsonProperty(ENABLE_CORS)
    protected boolean cors;
    @JsonProperty(CORS_MAX_AGE)
    protected int corsMaxAge = -1;
    @JsonProperty(CORS_ALLOWED_HEADERS)
    protected String corsAllowedHeaders;
    @JsonProperty(CORS_ALLOWED_METHODS)
    protected String corsAllowedMethods;
    @JsonProperty(CORS_EXPOSED_HEADERS)
    protected String corsExposedHeaders;
    @JsonProperty(EXPOSE_TOKEN)
    protected boolean exposeToken;
    @JsonProperty(BEARER_ONLY)
    protected boolean bearerOnly;
    @JsonProperty(AUTODETECT_BEARER_ONLY)
    protected boolean autodetectBearerOnly;
    @JsonProperty(ENABLE_BASIC_AUTH)
    protected boolean enableBasicAuth;
    @JsonProperty(PUBLIC_CLIENT)
    protected boolean publicClient;
    @JsonProperty(CREDENTIALS)
    protected Map<String, Object> credentials = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
    @JsonProperty(REDIRECT_REWRITE_RULES)
    protected Map<String, String> redirectRewriteRules;
    @JsonProperty(REALM)
    protected String realm;
    @JsonProperty(REALM_PUBLIC_KEY)
    protected String realmKey;
    @JsonProperty(AUTH_SERVER_URL)
    protected String authServerUrl;
    @JsonProperty(SSL_REQUIRED)
    protected String sslRequired;
    @JsonProperty(PROVIDER_URL)
    protected String providerUrl;
    @JsonProperty(CLIENT_ID_JSON_VALUE)
    protected String clientId;
    @JsonProperty(TOKEN_SIGNATURE_ALGORITHM)
    protected String tokenSignatureAlgorithm = DEFAULT_TOKEN_SIGNATURE_ALGORITHM;

    @JsonProperty(SCOPE)
    protected String scope;
    @JsonProperty(AUTHENTICATION_REQUEST_FORMAT)
    protected String authenticationRequestFormat;

    @JsonProperty(REQUEST_OBJECT_SIGNING_ALGORITHM)
    protected String requestObjectSigningAlgorithm;

    @JsonProperty(REQUEST_OBJECT_ENCRYPTION_ALG_VALUE)
    protected String requestObjectEncryptionAlgValue;

    @JsonProperty(REQUEST_OBJECT_ENCRYPTION_ENC_VALUE)
    protected String requestObjectEncryptionEncValue;

    /**
     * The Proxy url to use for requests to the auth-server, configurable via the adapter config property {@code proxy-url}.
     */
    @JsonProperty(PROXY_URL)
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

    public String getRequestObjectSigningKeyStoreFile() {
        return requestObjectSigningKeyStoreFile;
    }

    public void setRequestObjectSigningKeyStoreFile(String requestObjectSigningKeyStoreFile) {
        this.requestObjectSigningKeyStoreFile = requestObjectSigningKeyStoreFile;
    }
    public String getClientKeystore() {
        return clientKeystore;
    }

    public void setClientKeystore(String clientKeystore) {
        this.clientKeystore = clientKeystore;
    }

    public String getRequestObjectSigningKeyStoreType() {
        return requestObjectSigningKeyStoreType;
    }

    public void setRequestObjectSigningKeyStoreType(String requestObjectSigningKeyStoreType) {
        this.requestObjectSigningKeyStoreType = requestObjectSigningKeyStoreType;
    }

    public String getRequestObjectSigningKeyAlias() {
        return requestObjectSigningKeyAlias;
    }

    public void setRequestObjectSigningKeyAlias(String requestObjectSigningKeyAlias) {
        this.requestObjectSigningKeyAlias = requestObjectSigningKeyAlias;
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

    public String getRequestObjectSigningKeyPassword() {
        return requestObjectSigningKeyPassword;
    }

    public String getRequestObjectSigningKeyStorePassword() {
        return requestObjectSigningKeyStorePassword;
    }

    public void setClientKeyPassword(String clientKeyPassword) {
        this.clientKeyPassword = clientKeyPassword;
    }

    public void setRequestObjectSigningKeyStorePassword(String requestObjectSigningKeyStorePassword) {
        this.requestObjectSigningKeyStorePassword = requestObjectSigningKeyStorePassword;
    }

    public void setRequestObjectSigningKeyPassword(String requestObjectSigningKeyPassword) {
        this.requestObjectSigningKeyPassword = requestObjectSigningKeyPassword;
    }

    public int getConnectionPoolSize() {
        return connectionPoolSize;
    }

    public void setConnectionPoolSize(int connectionPoolSize) {
        this.connectionPoolSize = connectionPoolSize;
    }

    public int getConnectionTimeoutMillis() {
        return connectionTimeoutMillis;
    }

    public void setConnectionTimeoutMillis(int connectionTimeoutMillis) {
        this.connectionTimeoutMillis = connectionTimeoutMillis;
    }

    public int getConnectionTtlMillis() {
        return connectionTtlMillis;
    }

    public void setConnectionTtlMillis(int connectionTtlMillis) {
        this.connectionTtlMillis = connectionTtlMillis;
    }

    public int getSocketTimeoutMillis() {
        return socketTimeoutMillis;
    }

    public void setSocketTimeoutMillis(int socketTimeoutMillis) {
        this.socketTimeoutMillis = socketTimeoutMillis;
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
    public String getAuthenticationRequestFormat() {
        return authenticationRequestFormat;
    }

    public void setAuthenticationRequestFormat(String authenticationRequestFormat) {
        this.authenticationRequestFormat = authenticationRequestFormat;
    }

    public String getRequestObjectSigningAlgorithm() {
        return requestObjectSigningAlgorithm;
    }

    public void setRequestObjectSigningAlgorithm(String requestObjectSigningAlgorithm) {
        this.requestObjectSigningAlgorithm = requestObjectSigningAlgorithm;
    }

    public String getRequestObjectEncryptionAlgValue() {
        return requestObjectEncryptionAlgValue;
    }

    public void setRequestObjectEncryptionAlgValue(String requestObjectEncryptionAlgValue) {
        this.requestObjectEncryptionAlgValue = requestObjectEncryptionAlgValue;
    }

    public String getRequestObjectEncryptionEncValue() {
        return requestObjectEncryptionEncValue;
    }

    public void setRequestObjectEncryptionEncValue (String requestObjectEncryptionEncValue) {
        this.requestObjectEncryptionEncValue = requestObjectEncryptionEncValue;
    }
}

