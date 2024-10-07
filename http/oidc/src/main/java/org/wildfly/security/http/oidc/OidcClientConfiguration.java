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

import static org.apache.http.HttpHeaders.ACCEPT;
import static org.wildfly.security.http.oidc.ElytronMessages.log;
import static org.wildfly.security.http.oidc.Oidc.ACCOUNT_PATH;
import static org.wildfly.security.http.oidc.Oidc.CLIENTS_MANAGEMENT_REGISTER_NODE_PATH;
import static org.wildfly.security.http.oidc.Oidc.CLIENTS_MANAGEMENT_UNREGISTER_NODE_PATH;
import static org.wildfly.security.http.oidc.Oidc.DEFAULT_TOKEN_SIGNATURE_ALGORITHM;
import static org.wildfly.security.http.oidc.Oidc.DISCOVERY_PATH;
import static org.wildfly.security.http.oidc.Oidc.JSON_CONTENT_TYPE;
import static org.wildfly.security.http.oidc.Oidc.KEYCLOAK_REALMS_PATH;
import static org.wildfly.security.http.oidc.Oidc.SLASH;
import static org.wildfly.security.http.oidc.Oidc.SSLRequired;
import static org.wildfly.security.http.oidc.Oidc.TokenStore;
import static org.wildfly.security.jose.util.JsonSerialization.readValue;

import java.net.URI;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;

import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.util.EntityUtils;

/**
 * The OpenID Connect (OIDC) configuration for a client application. This class is based on
 * {@code org.keycloak.adapters.KeycloakDeployment}.
 *
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @author <a href="mailto:brad.culley@spartasystems.com">Brad Culley</a>
 * @author <a href="mailto:john.ament@spartasystems.com">John D. Ament</a>
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public class OidcClientConfiguration {

    public enum RelativeUrlsUsed {

        /**
         * Always use relative URI and resolve them later based on browser HTTP request
         */
        ALWAYS,

        /**
         * Relative URI not used. Configuration contains absolute URI.
         */
        NEVER;
    }

    protected RelativeUrlsUsed relativeUrls;
    protected String realm;
    protected PublicKeyLocator publicKeyLocator;
    protected String authServerBaseUrl;
    protected String providerUrl;
    protected String authUrl;
    protected String tokenUrl;
    protected String endSessionEndpointUrl;
    protected String accountUrl;
    protected String registerNodeUrl;
    protected String unregisterNodeUrl;
    protected String jwksUrl;
    protected String issuerUrl;
    protected String principalAttribute = "sub";
    protected List<String> requestObjectSigningAlgValuesSupported;
    protected List<String> requestObjectEncryptionEncValuesSupported;
    protected List<String> requestObjectEncryptionAlgValuesSupported;
    protected boolean requestParameterSupported;
    protected boolean requestUriParameterSupported;

    protected String resource;
    protected String clientId;
    protected boolean bearerOnly;
    protected boolean autodetectBearerOnly;
    protected boolean enableBasicAuth;
    protected boolean publicClient;
    protected Map<String, Object> resourceCredentials = new HashMap<>();
    protected ClientCredentialsProvider clientAuthenticator;
    protected Callable<HttpClient> client;

    protected String scope;
    protected SSLRequired sslRequired = SSLRequired.ALL;
    protected int confidentialPort = -1;
    protected TokenStore tokenStore = TokenStore.SESSION;
    protected String oidcStateCookiePath = "";
    protected String stateCookieName = "OAuth_Token_Request_State";
    protected boolean useResourceRoleMappings;
    protected boolean useRealmRoleMappings;
    protected boolean cors;
    protected int corsMaxAge = -1;
    protected String corsAllowedHeaders;
    protected String corsAllowedMethods;
    protected String corsExposedHeaders;
    protected boolean exposeToken;
    protected boolean alwaysRefreshToken;
    protected boolean registerNodeAtStartup;
    protected int registerNodePeriod;
    protected boolean turnOffChangeSessionIdOnLogin;

    protected volatile int notBefore;
    protected int tokenMinimumTimeToLive;
    protected int minTimeBetweenJwksRequests;
    protected int publicKeyCacheTtl;

    // https://tools.ietf.org/html/rfc7636
    protected boolean pkce = false;
    protected boolean ignoreOAuthQueryParameter;

    protected Map<String, String> redirectRewriteRules;

    protected boolean delegateBearerErrorResponseSending = false;
    protected boolean verifyTokenAudience = false;

    protected String tokenSignatureAlgorithm = DEFAULT_TOKEN_SIGNATURE_ALGORITHM;
    protected String authenticationRequestFormat;
    protected String requestObjectSigningAlgorithm;
    protected String requestObjectEncryptionAlgValue;
    protected String requestObjectEncryptionEncValue;
    protected String pushedAuthorizationRequestEndpoint;
    protected String requestObjectSigningKeyStoreFile;
    protected String requestObjectSigningKeyStorePassword;
    protected String requestObjectSigningKeyPassword;
    protected String requestObjectSigningKeyAlias;
    protected String requestObjectSigningKeyStoreType;
    protected JWKEncPublicKeyLocator encryptionPublicKeyLocator;

    private String postLogoutUri;

    private boolean sessionRequiredOnLogout = true;

    private String logoutUrl = "/logout";

    private String logoutCallbackUrl = "/logout/callback";

    private int logoutSessionWaitingLimit = 100;

    public OidcClientConfiguration() {
    }

    public boolean isConfigured() {
        return getResourceName() != null && getPublicKeyLocator() != null && (isBearerOnly() || (getAuthServerBaseUrl() != null || getProviderUrl() != null));
    }

    public String getResourceName() {
        return resource != null ? resource : clientId;
    }

    public String getResource() {
        return resource;
    }

    public String getClientId() {
        return clientId != null ? clientId : resource;
    }

    public String getRealm() {
        return realm;
    }

    public void setRealm(String realm) {
        this.realm = realm;
    }

    public PublicKeyLocator getPublicKeyLocator() {
        return publicKeyLocator;
    }

    public void setPublicKeyLocator(PublicKeyLocator publicKeyLocator) {
        this.publicKeyLocator = publicKeyLocator;
    }

    public String getAuthServerBaseUrl() {
        return authServerBaseUrl;
    }

    public void setProviderUrl(String providerUrl) {
        this.providerUrl = providerUrl;
        resetUrls();
    }


    public void setAuthServerBaseUrl(OidcJsonConfiguration config) {
        this.authServerBaseUrl = config.getAuthServerUrl();
        resetUrls();
    }

    /**
     * Resets all calculated urls to null and sets the relativeUrls field
     * depending the value of the current discovery URL in the configuration.
     * If it is relative is set to ALWAYS and if absolute is set to NEVER.
     */
    protected void resetUrls() {
        authUrl = null;
        tokenUrl = null;
        endSessionEndpointUrl = null;
        accountUrl = null;
        registerNodeUrl = null;
        unregisterNodeUrl = null;
        jwksUrl = null;
        relativeUrls = null;
        if (providerUrl != null || authServerBaseUrl != null) {
            try {
                URI uri = URI.create(providerUrl != null ? providerUrl : authServerBaseUrl);
                if (uri.getHost() == null) {
                    relativeUrls = RelativeUrlsUsed.ALWAYS;
                } else {
                    // We have absolute URI in config
                    relativeUrls = RelativeUrlsUsed.NEVER;
                }
            } catch (Exception e) {
                log.invalidAuthServerUrlOrProviderUrl(providerUrl != null ? providerUrl : authServerBaseUrl);
            }
        }
    }

    /**
     * URLs are loaded lazily when used.
     */
    protected void resolveUrls() {
        if (authUrl == null) {
            synchronized (this) {
                String discoveryUrl = getDiscoveryUrl();
                try {
                    log.debug("Loading OpenID provider metadata from " + discoveryUrl);

                    OidcProviderMetadata config = getOidcProviderMetadata(discoveryUrl);

                    authUrl = config.getAuthorizationEndpoint();
                    issuerUrl = config.getIssuer();
                    tokenUrl = config.getTokenEndpoint();
                    endSessionEndpointUrl = config.getLogoutEndpoint();
                    jwksUrl = config.getJwksUri();
                    requestParameterSupported = config.getRequestParameterSupported();
                    requestObjectSigningAlgValuesSupported = config.getRequestObjectSigningAlgValuesSupported();
                    requestObjectEncryptionEncValuesSupported = config.getRequestObjectEncryptionEncValuesSupported();
                    requestObjectEncryptionAlgValuesSupported = config.getRequestObjectEncryptionAlgValuesSupported();
                    requestUriParameterSupported = config.getRequestUriParameterSupported();
                    pushedAuthorizationRequestEndpoint = config.getPushedAuthorizationRequestEndpoint();

                    if (authServerBaseUrl != null) {
                        // keycloak-specific properties
                        accountUrl = getUrl(issuerUrl, ACCOUNT_PATH);
                        registerNodeUrl = getUrl(authServerBaseUrl, KEYCLOAK_REALMS_PATH + getRealm(), CLIENTS_MANAGEMENT_REGISTER_NODE_PATH);
                        unregisterNodeUrl = getUrl(authServerBaseUrl, KEYCLOAK_REALMS_PATH + getRealm(), CLIENTS_MANAGEMENT_UNREGISTER_NODE_PATH);
                    }
                    log.loadedOpenIdProviderMetadata(discoveryUrl);
                } catch (Exception e) {
                    log.unableToLoadOpenIdProviderMetadata(discoveryUrl);
                }
            }
        }
    }

    protected OidcProviderMetadata getOidcProviderMetadata(String discoveryUrl) throws Exception {
        HttpGet request = new HttpGet(discoveryUrl);
        request.addHeader(ACCEPT, JSON_CONTENT_TYPE);
        try {
            HttpResponse response = getClient().execute(request);
            if (response.getStatusLine().getStatusCode() != HttpStatus.SC_OK) {
                EntityUtils.consumeQuietly(response.getEntity());
                throw new Exception(response.getStatusLine().getReasonPhrase());
            }
            return readValue(response.getEntity().getContent(), OidcProviderMetadata.class);
        } finally {
            request.releaseConnection();
        }
    }

    private String getDiscoveryUrl() {
        if (providerUrl != null) {
            // generic OpenID provider configuration found
            return getUrl(providerUrl, DISCOVERY_PATH);
        } else if (authServerBaseUrl != null) {
            // keycloak-specific OpenID provider configuration found
            return getUrl(authServerBaseUrl, KEYCLOAK_REALMS_PATH + getRealm(), DISCOVERY_PATH);
        } else {
            throw log.providerUrlOrAuthServerUrlNeedsToBeConfigured();
        }
    }

    private static String getUrl(String baseUrl, String... paths) {
        StringBuilder sb = new StringBuilder(baseUrl);
        if (! baseUrl.endsWith(SLASH)) {
            sb.append(SLASH);
        }
        for (int i = 0; i < paths.length; i++) {
            sb.append(paths[i]);
            if (i != paths.length - 1) {
                sb.append(SLASH);
            }
        }
        return sb.toString();
    }

    public RelativeUrlsUsed getRelativeUrls() {
        return relativeUrls;
    }

    public String getProviderUrl() {
        if (providerUrl == null) {
            resolveUrls();
        }
        return providerUrl;
    }

    public String getAuthUrl() {
        resolveUrls();
        return authUrl;
    }

    public String getTokenUrl() {
        resolveUrls();
        return tokenUrl;
    }

    public String getEndSessionEndpointUrl() {
        resolveUrls();
        return endSessionEndpointUrl;
    }

    public String getAccountUrl() {
        resolveUrls();
        return accountUrl;
    }

    public String getRegisterNodeUrl() {
        resolveUrls();
        return registerNodeUrl;
    }

    public String getUnregisterNodeUrl() {
        resolveUrls();
        return unregisterNodeUrl;
    }

    public String getJwksUrl() {
        resolveUrls();
        return jwksUrl;
    }

    public String getIssuerUrl() {
        resolveUrls();
        return issuerUrl;
    }

    public List<String> getRequestObjectSigningAlgValuesSupported() {
        return requestObjectSigningAlgValuesSupported;
    }

    public List<String> getRequestObjectEncryptionAlgValuesSupported() {
        return requestObjectEncryptionAlgValuesSupported;
    }

    public List<String> getRequestObjectEncryptionEncValuesSupported() {
        return requestObjectEncryptionEncValuesSupported;
    }

    public boolean getRequestParameterSupported() {
        return requestParameterSupported;
    }

    public boolean getRequestUriParameterSupported() {
        return requestUriParameterSupported;
    }

    public void setResource(String resource) {
        this.resource = resource;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
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

    public boolean isPublicClient() {
        return publicClient;
    }

    public void setPublicClient(boolean publicClient) {
        this.publicClient = publicClient;
    }

    public Map<String, Object> getResourceCredentials() {
        return resourceCredentials;
    }

    public void setResourceCredentials(Map<String, Object> resourceCredentials) {
        this.resourceCredentials = resourceCredentials;
    }

    public ClientCredentialsProvider getClientAuthenticator() {
        return clientAuthenticator;
    }

    public void setClientAuthenticator(ClientCredentialsProvider clientAuthenticator) {
        this.clientAuthenticator = clientAuthenticator;
    }

    public HttpClient getClient() {
        try {
            return client.call();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public void setClient(final HttpClient client) {
        this.client = new Callable<HttpClient>() {
            @Override
            public HttpClient call() {
                return client;
            }
        };
    }

    public String getScope() {
        return scope;
    }

    public void setScope(String scope) {
        this.scope = scope;
    }

    public SSLRequired getSSLRequired() {
        return sslRequired;
    }

    public void setSSLRequired(SSLRequired sslRequired) {
        this.sslRequired = sslRequired;
    }

    public boolean isSSLEnabled() {
        return SSLRequired.NONE != sslRequired;
    }

    public int getConfidentialPort() {
        return confidentialPort;
    }

    public void setConfidentialPort(int confidentialPort) {
        this.confidentialPort = confidentialPort;
    }

    public TokenStore getTokenStore() {
        return tokenStore;
    }

    public void setTokenStore(TokenStore tokenStore) {
        this.tokenStore = tokenStore;
    }

    public String getOidcStateCookiePath() {
        return oidcStateCookiePath;
    }

    public void setOidcStateCookiePath(String oidcStateCookiePath) {
        this.oidcStateCookiePath = oidcStateCookiePath;
    }

    public String getStateCookieName() {
        return stateCookieName;
    }

    public void setStateCookieName(String stateCookieName) {
        this.stateCookieName = stateCookieName;
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

    public int getNotBefore() {
        return notBefore;
    }

    public void setNotBefore(int notBefore) {
        this.notBefore = notBefore;
    }

    public void updateNotBefore(int notBefore) {
        this.notBefore = notBefore;
        getPublicKeyLocator().reset(this);
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

    public String getPrincipalAttribute() {
        return principalAttribute;
    }

    public void setPrincipalAttribute(String principalAttribute) {
        this.principalAttribute = principalAttribute;
    }

    public boolean isTurnOffChangeSessionIdOnLogin() {
        return turnOffChangeSessionIdOnLogin;
    }

    public void setTurnOffChangeSessionIdOnLogin(boolean turnOffChangeSessionIdOnLogin) {
        this.turnOffChangeSessionIdOnLogin = turnOffChangeSessionIdOnLogin;
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

    public void setIgnoreOAuthQueryParameter(boolean ignoreOAuthQueryParameter) {
        this.ignoreOAuthQueryParameter = ignoreOAuthQueryParameter;
    }

    public boolean isOAuthQueryParameterEnabled() {
        return !this.ignoreOAuthQueryParameter;
    }

    public Map<String, String> getRedirectRewriteRules() {
        return redirectRewriteRules;
    }

    public void setRewriteRedirectRules(Map<String, String> redirectRewriteRules) {
        this.redirectRewriteRules = redirectRewriteRules;
    }

    public boolean isDelegateBearerErrorResponseSending() {
        return delegateBearerErrorResponseSending;
    }

    public void setDelegateBearerErrorResponseSending(boolean delegateBearerErrorResponseSending) {
        this.delegateBearerErrorResponseSending = delegateBearerErrorResponseSending;
    }

    public boolean isVerifyTokenAudience() {
        return verifyTokenAudience;
    }

    public void setVerifyTokenAudience(boolean verifyTokenAudience) {
        this.verifyTokenAudience = verifyTokenAudience;
    }

    public void setClient(Callable<HttpClient> callable) {
        client = callable;
    }

    public void setTokenSignatureAlgorithm(String tokenSignatureAlgorithm) {
        this.tokenSignatureAlgorithm = tokenSignatureAlgorithm;
    }

    public String getTokenSignatureAlgorithm() {
        return tokenSignatureAlgorithm;
    }

    public void setPostLogoutUri(String postLogoutUri) {
        this.postLogoutUri = postLogoutUri;
    }

    public String getPostLogoutUri() {
        return postLogoutUri;
    }

    public boolean isSessionRequiredOnLogout() {
        return sessionRequiredOnLogout;
    }

    public void setSessionRequiredOnLogout(boolean sessionRequiredOnLogout) {
        this.sessionRequiredOnLogout = sessionRequiredOnLogout;
    }

    public String getLogoutUrl() {
        return logoutUrl;
    }

    public void setLogoutUrl(String logoutUrl) {
        this.logoutUrl = logoutUrl;
    }

    public String getLogoutCallbackUrl() {
        return logoutCallbackUrl;
    }

    public void setLogoutCallbackUrl(String logoutCallbackUrl) {
        this.logoutCallbackUrl = logoutCallbackUrl;
    }
    public int getLogoutSessionWaitingLimit() {
        return logoutSessionWaitingLimit;
    }

    public void setLogoutSessionWaitingLimit(int logoutSessionWaitingLimit) {
        this.logoutSessionWaitingLimit = logoutSessionWaitingLimit;
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

    public void setRequestObjectEncryptionEncValue(String requestObjectEncryptionEncValue) {
        this.requestObjectEncryptionEncValue = requestObjectEncryptionEncValue;
    }

    public String getRequestObjectSigningKeyStoreFile() {
        return requestObjectSigningKeyStoreFile;
    }

    public void setRequestObjectSigningKeyStoreFile(String keyStoreFile) {
        this.requestObjectSigningKeyStoreFile = keyStoreFile;
    }

    public String getRequestObjectSigningKeyStorePassword() {
        return requestObjectSigningKeyStorePassword;
    }

    public void setRequestObjectSigningKeyStorePassword(String requestObjectSigningKeyStorePassword) {
        this.requestObjectSigningKeyStorePassword = requestObjectSigningKeyStorePassword;
    }

    public String getRequestObjectSigningKeyPassword() {
        return requestObjectSigningKeyPassword;
    }

    public void setRequestObjectSigningKeyPassword(String requestObjectSigningKeyPassword) {
        this.requestObjectSigningKeyPassword = requestObjectSigningKeyPassword;
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

    public String getPushedAuthorizationRequestEndpoint() {
        return pushedAuthorizationRequestEndpoint;
    }

    public void setPushedAuthorizationRequestEndpoint(String pushedAuthorizationRequestEndpoint) {
        this.pushedAuthorizationRequestEndpoint = pushedAuthorizationRequestEndpoint;
    }

    public void setEncryptionPublicKeyLocator(JWKEncPublicKeyLocator publicKeySetExtractor) {
        this.encryptionPublicKeyLocator = publicKeySetExtractor;
    }

    public JWKEncPublicKeyLocator getEncryptionPublicKeyLocator() {
        return this.encryptionPublicKeyLocator;
    }
}
