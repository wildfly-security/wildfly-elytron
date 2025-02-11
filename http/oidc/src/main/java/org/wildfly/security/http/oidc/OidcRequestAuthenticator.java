/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2021 Red Hat, Inc., and individual contributors
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

import static org.jose4j.jws.AlgorithmIdentifiers.HMAC_SHA256;
import static org.jose4j.jws.AlgorithmIdentifiers.HMAC_SHA384;
import static org.jose4j.jws.AlgorithmIdentifiers.HMAC_SHA512;
import static org.jose4j.jws.AlgorithmIdentifiers.NONE;
import static org.wildfly.security.http.oidc.ElytronMessages.log;
import static org.wildfly.security.http.oidc.IDToken.NONCE;
import static org.wildfly.security.http.oidc.Oidc.ALLOW_QUERY_PARAMS_PROPERTY_NAME;
import static org.wildfly.security.http.oidc.Oidc.CLIENT_ID;
import static org.wildfly.security.http.oidc.Oidc.CODE;
import static org.wildfly.security.http.oidc.Oidc.DOMAIN_HINT;
import static org.wildfly.security.http.oidc.Oidc.ERROR;
import static org.wildfly.security.http.oidc.Oidc.ISSUER;
import static org.wildfly.security.http.oidc.Oidc.KC_IDP_HINT;
import static org.wildfly.security.http.oidc.Oidc.LOGIN_HINT;
import static org.wildfly.security.http.oidc.Oidc.MAX_AGE;
import static org.wildfly.security.http.oidc.Oidc.OIDC_SCOPE;
import static org.wildfly.security.http.oidc.Oidc.PROMPT;
import static org.wildfly.security.http.oidc.Oidc.REDIRECT_URI;
import static org.wildfly.security.http.oidc.Oidc.RESPONSE_TYPE;
import static org.wildfly.security.http.oidc.Oidc.REQUEST;
import static org.wildfly.security.http.oidc.Oidc.REQUEST_URI;
import static org.wildfly.security.http.oidc.Oidc.SCOPE;
import static org.wildfly.security.http.oidc.Oidc.SESSION_RANDOM_VALUE;
import static org.wildfly.security.http.oidc.Oidc.SESSION_STATE;
import static org.wildfly.security.http.oidc.Oidc.STATE;
import static org.wildfly.security.http.oidc.Oidc.UI_LOCALES;
import static org.wildfly.security.http.oidc.Oidc.ClientCredentialsProviderType.SECRET;

import static org.wildfly.security.http.oidc.Oidc.logToken;
import static org.wildfly.security.http.oidc.Oidc.generateId;
import static org.wildfly.security.http.oidc.Oidc.getQueryParamValue;
import static org.wildfly.security.http.oidc.Oidc.stripQueryParam;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.http.NameValuePair;
import org.apache.http.HttpStatus;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.message.BasicNameValuePair;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.keys.HmacKey;
import org.jose4j.lang.JoseException;
import org.wildfly.common.iteration.ByteIterator;
import org.wildfly.security.http.HttpConstants;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public class OidcRequestAuthenticator {
    protected OidcClientConfiguration deployment;
    protected RequestAuthenticator reqAuthenticator;
    protected int sslRedirectPort;
    protected OidcTokenStore tokenStore;
    protected String tokenString;
    protected String idTokenString;
    protected IDToken idToken;
    protected AccessToken token;
    protected OidcHttpFacade facade;
    protected AuthChallenge challenge;
    protected String refreshToken;
    protected String strippedOauthParametersRequestUri;

    private int NONCE_SIZE = 36;

    static final boolean ALLOW_QUERY_PARAMS_PROPERTY;

    static {
        ALLOW_QUERY_PARAMS_PROPERTY = AccessController.doPrivileged(new PrivilegedAction<Boolean>() {
            @Override
            public Boolean run() {
                return Boolean.parseBoolean(System.getProperty(ALLOW_QUERY_PARAMS_PROPERTY_NAME, "false"));
            }
        });
    }

    public OidcRequestAuthenticator(RequestAuthenticator requestAuthenticator, OidcHttpFacade facade, OidcClientConfiguration deployment, int sslRedirectPort, OidcTokenStore tokenStore) {
        this.reqAuthenticator = requestAuthenticator;
        this.facade = facade;
        this.deployment = deployment;
        this.sslRedirectPort = deployment.getConfidentialPort() != -1 ? deployment.getConfidentialPort() : sslRedirectPort;
        this.tokenStore = tokenStore;
    }

    public AuthChallenge getChallenge() {
        return challenge;
    }

    public String getTokenString() {
        return tokenString;
    }

    public AccessToken getToken() {
        return token;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public String getIDTokenString() {
        return idTokenString;
    }

    public void setIDTokenString(String idTokenString) {
        this.idTokenString = idTokenString;
    }

    public IDToken getIDToken() {
        return idToken;
    }

    public void setIDToken(IDToken idToken) {
        this.idToken = idToken;
    }

    public String getStrippedOauthParametersRequestUri() {
        return strippedOauthParametersRequestUri;
    }

    public void setStrippedOauthParametersRequestUri(String strippedOauthParametersRequestUri) {
        this.strippedOauthParametersRequestUri = strippedOauthParametersRequestUri;
    }

    protected String getRequestUrl() {
        return facade.getRequest().getURI();
    }

    protected boolean isRequestSecure() {
        return facade.getRequest().isSecure();
    }

    protected OidcHttpFacade.Cookie getCookie(String cookieName) {
        return facade.getRequest().getCookie(cookieName);
    }

    protected String getCookieValue(String cookieName) {
        OidcHttpFacade.Cookie cookie = getCookie(cookieName);
        if (cookie == null) return null;
        return cookie.getValue();
    }

    protected String getError() {
        return getQueryParamValue(facade, ERROR);
    }

    protected String getCode() {
        return getQueryParamValue(facade, CODE);
    }

    protected String getRedirectUri(String state, String sessionRandomValueHash) {
        String url = getRequestUrl();
        log.debugf("callback uri: %s", url);

        try {
            if (! facade.getRequest().isSecure() && deployment.getSSLRequired().isRequired(facade.getRequest().getRemoteAddr())) {
                int port = getSSLRedirectPort();
                if (port < 0) {
                    // disabled?
                    return null;
                }
                URIBuilder uriBuilder = new URIBuilder(url).setScheme("https");
                if (port != 443) {
                    uriBuilder.setPort(port);
                }
                url = uriBuilder.build().toString();
            }

            List<String> forwardableQueryParams = Arrays.asList(LOGIN_HINT, DOMAIN_HINT, KC_IDP_HINT, PROMPT, MAX_AGE, UI_LOCALES, SCOPE);
            List<NameValuePair> forwardedQueryParams = new ArrayList<>(forwardableQueryParams.size());
            Set<String> allScopes = new HashSet<>();
            addScopes(deployment.getScope(), allScopes);

            for (String paramName : forwardableQueryParams) {
                String paramValue = getQueryParamValue(facade, paramName);
                if (SCOPE.equals(paramName)) {
                    paramValue = combineAndReorderScopes(allScopes, paramValue);
                }
                if (paramValue != null && !paramValue.isEmpty()) {
                    forwardedQueryParams.add(new BasicNameValuePair(paramName, paramValue));
                }
                url = stripQueryParam(url, paramName);
            }

            if (deployment.getAuthUrl() == null) {
                return null;
            }

            String redirectUri = rewrittenRedirectUri(url);
            URIBuilder redirectUriBuilder = new URIBuilder(deployment.getAuthUrl());
            redirectUriBuilder.addParameter(RESPONSE_TYPE, CODE)
                    .addParameter(CLIENT_ID, deployment.getResourceName());

            switch (deployment.getAuthenticationRequestFormat()) {
                case REQUEST:
                    if (deployment.getRequestParameterSupported()) {
                        // add request objects into request parameter
                        try {
                            createRequestWithRequestParameter(REQUEST, redirectUriBuilder, redirectUri, state, forwardedQueryParams, sessionRandomValueHash);
                        } catch (IOException | JoseException e) {
                            throw log.unableToCreateRequestWithRequestParameter(e);
                        }
                    } else {
                        // send request as usual
                        createOAuthRequest(redirectUriBuilder, redirectUri, state, forwardedQueryParams, sessionRandomValueHash);
                        log.requestParameterNotSupported();
                    }
                    break;
                case REQUEST_URI:
                    if (deployment.getRequestUriParameterSupported()) {
                        try {
                            createRequestWithRequestParameter(REQUEST_URI, redirectUriBuilder, redirectUri, state, forwardedQueryParams, sessionRandomValueHash);
                        } catch (IOException | JoseException e) {
                            throw log.unableToCreateRequestUriWithRequestParameter(e);
                        }
                    } else {
                        // send request as usual
                        createOAuthRequest(redirectUriBuilder, redirectUri, state, forwardedQueryParams, sessionRandomValueHash);
                        log.requestParameterNotSupported();
                    }
                    break;
                default:
                    createOAuthRequest(redirectUriBuilder, redirectUri, state, forwardedQueryParams, sessionRandomValueHash);
                    break;
            }
            return redirectUriBuilder.build().toString();
        } catch (URISyntaxException e) {
            throw log.unableToCreateRedirectResponse(e);
        }
    }

    protected URIBuilder createOAuthRequest(URIBuilder redirectUriBuilder, String redirectUri, String state, List<NameValuePair> forwardedQueryParams, String sessionRandomValueHash) {
        redirectUriBuilder.addParameter(REDIRECT_URI, redirectUri)
                .addParameter(STATE, state)
                .addParameters(forwardedQueryParams)
                .addParameter(NONCE, sessionRandomValueHash);
        return redirectUriBuilder;
    }

    protected URIBuilder createRequestWithRequestParameter(String requestFormat, URIBuilder redirectUriBuilder, String redirectUri, String state, List<NameValuePair> forwardedQueryParams, String sessionRandomValueHash) throws JoseException, IOException {
        String request = convertToRequestParameter(redirectUriBuilder, redirectUri, state, forwardedQueryParams, sessionRandomValueHash);

        switch (requestFormat) {
            case REQUEST:
                redirectUriBuilder.addParameter(REDIRECT_URI, redirectUri)
                        .addParameter(REQUEST, request);
                break;
            case REQUEST_URI:
                String request_uri = ServerRequest.getRequestUri(request, deployment);
                redirectUriBuilder.addParameter("request_uri", request_uri)
                        .addParameter(REDIRECT_URI, redirectUri);
                break;
        }
        return redirectUriBuilder;
    }

    protected int getSSLRedirectPort() {
        return sslRedirectPort;
    }

    protected String getStateCode() {
        return generateId();
    }

    protected AuthChallenge loginRedirect() {
        final String state = getStateCode();
        final String sessionRandomValue = generateSessionRandomValue();
        final String redirect = getRedirectUri(state, Oidc.getCryptographicValue(sessionRandomValue));
        if (redirect == null) {
            return challenge(HttpStatus.SC_FORBIDDEN, AuthenticationError.Reason.NO_REDIRECT_URI, null);
        }
        return new AuthChallenge() {

            @Override
            public int getResponseCode() {
                return 0;
            }

            @Override
            public boolean challenge(OidcHttpFacade exchange) {
                tokenStore.saveRequest();
                log.debug("Sending redirect to login page: " + redirect);
                exchange.getResponse().setStatus(HttpStatus.SC_MOVED_TEMPORARILY);
                exchange.getResponse().setCookie(deployment.getStateCookieName(), state, "/", null, -1, deployment.getSSLRequired().isRequired(facade.getRequest().getRemoteAddr()), true);
                exchange.getResponse().setHeader(HttpConstants.LOCATION, redirect);
                exchange.getResponse().setCookie(SESSION_RANDOM_VALUE, sessionRandomValue, "/", null, -1, deployment.getSSLRequired().isRequired(facade.getRequest().getRemoteAddr()), true);

                return true;
            }
        };
    }

    protected AuthChallenge checkStateCookie() {
        OidcHttpFacade.Cookie stateCookie = getCookie(deployment.getStateCookieName());

        if (stateCookie == null) {
            log.warn("No state cookie");
            return challenge(HttpStatus.SC_BAD_REQUEST, AuthenticationError.Reason.INVALID_STATE_COOKIE, null);
        }
        // reset the cookie
        log.debug("** reseting application state cookie");
        facade.getResponse().resetCookie(deployment.getStateCookieName(), stateCookie.getPath());
        String stateCookieValue = getCookieValue(deployment.getStateCookieName());

        String state = getQueryParamValue(facade, STATE);
        if (state == null) {
            log.warn("state parameter was null");
            return challenge(HttpStatus.SC_BAD_REQUEST, AuthenticationError.Reason.INVALID_STATE_COOKIE, null);
        }

        if (!state.equals(stateCookieValue)) {
            log.warn("state parameter invalid");
            log.warn("cookie: " + stateCookieValue);
            log.warn("queryParam: " + state);
            return challenge(HttpStatus.SC_BAD_REQUEST, AuthenticationError.Reason.INVALID_STATE_COOKIE, null);
        }
        return null;

    }

    public Oidc.AuthOutcome authenticate() {
        String code = getCode();
        if (code == null) {
            log.debug("there was no code");
            String error = getError();
            if (error != null) {
                log.warn("There was an error: " + error);
                challenge = challenge(HttpStatus.SC_BAD_REQUEST, AuthenticationError.Reason.OAUTH_ERROR, error);
                return Oidc.AuthOutcome.FAILED;
            } else {
                log.debug("redirecting to auth server");
                challenge = loginRedirect();
                return Oidc.AuthOutcome.NOT_ATTEMPTED;
            }
        } else {
            log.debug("there was a code, resolving");
            challenge = resolveCode(code);
            if (challenge != null) {
                return Oidc.AuthOutcome.FAILED;
            }
            return Oidc.AuthOutcome.AUTHENTICATED;
        }

    }

    protected AuthChallenge challenge(final int code, final AuthenticationError.Reason reason, final String description) {
        return new AuthChallenge() {
            @Override
            public int getResponseCode() {
                return code;
            }

            @Override
            public boolean challenge(OidcHttpFacade exchange) {
                AuthenticationError error = new AuthenticationError(reason, description);
                exchange.getRequest().setError(error);
                exchange.getResponse().sendError(code);
                return true;
            }
        };
    }

    /**
     * Start or continue the oauth login process.
     * <p/>
     * If code query parameter is not present, then browser is redirected to authUrl. The redirect URL will be
     * the URL of the current request.
     * <p/>
     * If code query parameter is present, then an access token is obtained by invoking a secure request to the codeUrl.
     * If the access token is obtained, the browser is again redirected to the current request URL, but any OAuth
     * protocol specific query parameters are removed.
     *
     * @return null if an access token was obtained, otherwise a challenge is returned
     */
    protected AuthChallenge resolveCode(String code) {
        // abort if not HTTPS
        if (! isRequestSecure() && deployment.getSSLRequired().isRequired(facade.getRequest().getRemoteAddr())) {
            log.error("SSL required. Request: " + facade.getRequest().getURI());
            return challenge(HttpStatus.SC_FORBIDDEN, AuthenticationError.Reason.SSL_REQUIRED, null);
        }

        log.debug("checking state cookie for after code");
        AuthChallenge challenge = checkStateCookie();
        if (challenge != null) return challenge;

        AccessAndIDTokenResponse tokenResponse;
        strippedOauthParametersRequestUri = rewrittenRedirectUri(stripOauthParametersFromRedirect(facade.getRequest().getURI()));

        try {
            tokenResponse = ServerRequest.invokeAccessCodeToToken(deployment, code, strippedOauthParametersRequestUri);
        } catch (ServerRequest.HttpFailure failure) {
            log.error("failed to turn code into token");
            log.error("status from server: " + failure.getStatus());
            if (failure.getError() != null && !failure.getError().trim().isEmpty()) {
                log.error("   " + failure.getError());
            }
            return challenge(HttpStatus.SC_FORBIDDEN, AuthenticationError.Reason.CODE_TO_TOKEN_FAILURE, null);

        } catch (IOException e) {
            log.error("failed to turn code into token", e);
            return challenge(HttpStatus.SC_FORBIDDEN, AuthenticationError.Reason.CODE_TO_TOKEN_FAILURE, null);
        }

        tokenString = tokenResponse.getAccessToken();
        refreshToken = tokenResponse.getRefreshToken();
        idTokenString = tokenResponse.getIDToken();

        log.debug("Verifying tokens");

        logToken("\taccess_token", tokenString);
        logToken("\tid_token", idTokenString);
        logToken("\trefresh_token", refreshToken);

        try {
            TokenValidator tokenValidator = TokenValidator.builder(deployment).build();

            TokenValidator.VerifiedTokens verifiedTokens = tokenValidator.parseAndVerifyToken(idTokenString, tokenString,
                    facade.getRequest().getCookie(SESSION_RANDOM_VALUE));
            idToken = verifiedTokens.getIdToken();
            token = verifiedTokens.getAccessToken();

            log.debug("Token Verification succeeded!");
        } catch (OidcException e) {
            log.failedVerificationOfToken(e.getMessage());
            return challenge(HttpStatus.SC_FORBIDDEN, AuthenticationError.Reason.INVALID_TOKEN, null);
        }
        if (tokenResponse.getNotBeforePolicy() > deployment.getNotBefore()) { // Keycloak specific
            deployment.updateNotBefore(tokenResponse.getNotBeforePolicy());
        }
        if (token.getIssuedAt() < deployment.getNotBefore()) {
            log.error("Stale token");
            return challenge(HttpStatus.SC_FORBIDDEN, AuthenticationError.Reason.STALE_TOKEN, null);
        }

        log.debug("successfully authenticated");
        return null;
    }

    private static String stripOauthParametersFromRedirect(String uri) {
        uri = stripQueryParam(uri, CODE);
        uri = stripQueryParam(uri, STATE);
        uri = stripQueryParam(uri, SESSION_STATE);
        return stripQueryParam(uri, ISSUER);
    }

    private String rewrittenRedirectUri(String originalUri) {
        Map<String, String> rewriteRules = deployment.getRedirectRewriteRules();
        if (ALLOW_QUERY_PARAMS_PROPERTY && (rewriteRules == null || rewriteRules.isEmpty())) {
            return originalUri;
        }
        try {
            URL url = new URL(originalUri);
            Map.Entry<String, String> rule = null;
            if (rewriteRules != null && ! rewriteRules.isEmpty()) {
                rule =  rewriteRules.entrySet().iterator().next();
            }
            StringBuilder redirectUriBuilder = new StringBuilder(url.getProtocol());
            redirectUriBuilder.append("://").append(url.getAuthority());
            if (rule != null) {
                redirectUriBuilder.append(url.getPath().replaceFirst(rule.getKey(), rule.getValue()));
            } else {
                redirectUriBuilder.append(url.getPath());
            }
            return redirectUriBuilder.toString();
        } catch (MalformedURLException ex) {
            log.error("Not a valid request url");
            throw new RuntimeException(ex);
        }
    }

    private static String addOidcScopeIfNeeded(String scope) {
        if (scope == null || scope.isEmpty()) {
            return OIDC_SCOPE;
        } else if (hasScope(scope, OIDC_SCOPE)) {
            return scope;
        } else {
            return OIDC_SCOPE + " " + scope;
        }
    }

    private static boolean hasScope(String scopeParam, String targetScope) {
        if (scopeParam == null || targetScope == null) {
            return false;
        }
        String[] scopes = scopeParam.split(" ");
        for (String scope : scopes) {
            if (targetScope.equals(scope)) {
                return true;
            }
        }
        return false;
    }

    private String combineAndReorderScopes(Set<String> allScopes, String paramValue) {
        StringBuilder combinedScopes = new StringBuilder();
        addScopes(paramValue, allScopes);

        //some OpenID providers require openid scope to be added in the beginning
        combinedScopes.append(OIDC_SCOPE);
        for (String scope : allScopes) {
            if (!scope.equals(OIDC_SCOPE)) {
                combinedScopes.append(" ").append(scope);
            }
        }
        return combinedScopes.toString();
    }

    private void addScopes(String scopes, Set<String> allScopes) {
        if (scopes != null && !scopes.isEmpty()) {
            allScopes.addAll(Arrays.asList(scopes.split("\\s+")));
        }
    }

    private String convertToRequestParameter(URIBuilder redirectUriBuilder, String redirectUri, String state, List<NameValuePair> forwardedQueryParams, String sessionRandomValueHash) throws JoseException, IOException {
        redirectUriBuilder.addParameter(SCOPE, OIDC_SCOPE);

        JwtClaims jwtClaims = new JwtClaims();
        jwtClaims.setIssuer(deployment.getResourceName());
        jwtClaims.setAudience(deployment.getIssuerUrl());

        for ( NameValuePair parameter: forwardedQueryParams) {
            jwtClaims.setClaim(parameter.getName(), parameter.getValue());
        }

        jwtClaims.setClaim(STATE, state);
        jwtClaims.setClaim(REDIRECT_URI, redirectUri);
        jwtClaims.setClaim(RESPONSE_TYPE, CODE);
        jwtClaims.setClaim(CLIENT_ID, deployment.getResourceName());
        jwtClaims.setClaim(NONCE, sessionRandomValueHash);

        // sign JWT first before encrypting
        JsonWebSignature signedRequest = signRequest(jwtClaims, deployment);

        // Encrypting optional
        if (deployment.getRequestObjectEncryptionAlgValue() != null && !deployment.getRequestObjectEncryptionAlgValue().isEmpty() &&
            deployment.getRequestObjectEncryptionEncValue() != null && !deployment.getRequestObjectEncryptionEncValue().isEmpty()) {
            return encryptRequest(signedRequest).getCompactSerialization();
        } else {
            return signedRequest.getCompactSerialization();
        }
    }

    private static KeyPair getkeyPair(OidcClientConfiguration deployment) throws IOException {
        if (!deployment.getRequestObjectSigningAlgorithm().equals(NONE) && deployment.getRequestObjectSigningKeyStoreFile() == null){
            throw log.invalidKeyStoreConfiguration();
        } else {
            return JWTSigningUtils.loadKeyPairFromKeyStore(deployment.getRequestObjectSigningKeyStoreFile(),
                    deployment.getRequestObjectSigningKeyStorePassword(), deployment.getRequestObjectSigningKeyPassword(),
                    deployment.getRequestObjectSigningKeyAlias(), deployment.getRequestObjectSigningKeyStoreType());
        }
    }

    private static JsonWebSignature signRequest(JwtClaims jwtClaims, OidcClientConfiguration deployment) throws IOException, JoseException {
        JsonWebSignature jsonWebSignature = new JsonWebSignature();
        jsonWebSignature.setPayload(jwtClaims.toJson());

        if (!deployment.getRequestObjectSigningAlgValuesSupported().contains(deployment.getRequestObjectSigningAlgorithm())) {
            throw log.invalidRequestObjectSignatureAlgorithm();
        } else {
            if (deployment.getRequestObjectSigningAlgorithm().equals(NONE)) { //unsigned
                jsonWebSignature.setAlgorithmConstraints(AlgorithmConstraints.NO_CONSTRAINTS);
                jsonWebSignature.setAlgorithmHeaderValue(NONE);
            } else if (deployment.getRequestObjectSigningAlgorithm().equals(HMAC_SHA256)
                    || deployment.getRequestObjectSigningAlgorithm().equals(HMAC_SHA384)
                    || deployment.getRequestObjectSigningAlgorithm().equals(HMAC_SHA512)) { //signed with symmetric key
                jsonWebSignature.setAlgorithmHeaderValue(deployment.getRequestObjectSigningAlgorithm());
                String secretKey = (String) deployment.getResourceCredentials().get(SECRET.getValue());
                if (secretKey == null) {
                    throw log.clientSecretNotConfigured();
                } else {
                    Key key = new HmacKey(secretKey.getBytes(StandardCharsets.UTF_8));   //the client secret is a shared secret between the server and the client
                    jsonWebSignature.setKey(key);
                }
            } else { //signed with asymmetric key
                KeyPair keyPair = getkeyPair(deployment);
                jsonWebSignature.setKey(keyPair.getPrivate());
                jsonWebSignature.setAlgorithmHeaderValue(deployment.getRequestObjectSigningAlgorithm());
            }
            if (!deployment.getRequestObjectSigningAlgorithm().equals(NONE))
                jsonWebSignature.sign();
            else
                log.unsignedRequestObjectIsUsed();
            return jsonWebSignature;
        }
    }

    private JsonWebEncryption encryptRequest(JsonWebSignature signedRequest) throws JoseException, IOException {
        if (!deployment.getRequestObjectEncryptionAlgValuesSupported().contains(deployment.getRequestObjectEncryptionAlgValue())) {
            throw log.invalidRequestObjectEncryptionAlgorithm();
        } else if (!deployment.getRequestObjectEncryptionEncValuesSupported().contains(deployment.getRequestObjectEncryptionEncValue())) {
            throw log.invalidRequestObjectEncryptionEncValue();
        } else {
            JsonWebEncryption jsonEncryption = new JsonWebEncryption();
            jsonEncryption.setPayload(signedRequest.getCompactSerialization());
            jsonEncryption.setAlgorithmConstraints(new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.PERMIT, deployment.getRequestObjectEncryptionAlgValue(), deployment.getRequestObjectEncryptionEncValue()));
            jsonEncryption.setAlgorithmHeaderValue(deployment.getRequestObjectEncryptionAlgValue());
            jsonEncryption.setEncryptionMethodHeaderParameter(deployment.getRequestObjectEncryptionEncValue());
            PublicKey encPublicKey = deployment.getEncryptionPublicKeyLocator().getPublicKey(null, deployment);
            jsonEncryption.setKey(encPublicKey);
            return jsonEncryption;
        }
    }

    private String generateSessionRandomValue() {
        SecureRandom random = new SecureRandom();
        byte[] nonceData = new byte[NONCE_SIZE];
        random.nextBytes(nonceData);
        return ByteIterator.ofBytes(nonceData).base64Encode().drainToString();
    }
}
