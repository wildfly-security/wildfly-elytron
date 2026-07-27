/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2024 Red Hat, Inc., and individual contributors
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

import static java.util.Collections.synchronizedMap;
import static org.wildfly.security.http.HttpConstants.NONCE;
import static org.wildfly.security.http.oidc.ElytronMessages.log;

import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.LinkedHashMap;
import java.util.Map;

import org.apache.http.HttpStatus;
import org.apache.http.client.utils.URIBuilder;
import org.jose4j.jwt.JwtClaims;
import org.wildfly.security.http.HttpConstants;
import org.wildfly.security.http.HttpScope;
import org.wildfly.security.http.Scope;
import org.wildfly.security.http.oidc.OidcHttpFacade.Request;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
final class LogoutHandler {

    private static final String POST_LOGOUT_REDIRECT_URI_PARAM = "post_logout_redirect_uri";
    private static final String ID_TOKEN_HINT_PARAM = "id_token_hint";
    private static final String LOGOUT_TOKEN_PARAM = "logout_token";
    private static final String LOGOUT_JWT_TOKEN_TYPE = "logout+jwt";
    private static final String KEYCLOCK_LOGOUT_TOKEN_TYPE = "Logout";
    private static final String CLIENT_ID_SID_SEPARATOR = "-";
    private static final String SID = "sid";
    private static final String ISS = "iss";

    /**
     * A bounded map to store sessions marked for invalidation after receiving logout requests through the back-channel
     */
    private Map<String, OidcClientConfiguration> sessionsMarkedForInvalidation = synchronizedMap(new LinkedHashMap<String, OidcClientConfiguration>(16, 0.75f, true) {
        @Override
        protected boolean removeEldestEntry(Map.Entry<String, OidcClientConfiguration> eldest) {
            boolean remove = sessionsMarkedForInvalidation.size() > eldest.getValue().getBackChannelLogoutSessionInvalidationLimit();

            if (remove) {
                log.debugf("Limit [%s] reached for sessions waiting [%s] for logout", eldest.getValue().getBackChannelLogoutSessionInvalidationLimit(), sessionsMarkedForInvalidation.size());
            }

            return remove;
        }
    });

    boolean tryLogout(OidcHttpFacade facade) {
        if (isLogoutCallbackPath(facade)) {
            log.trace("isLogoutCallbackPath");
            if (isFrontChannel(facade)) {
                log.trace("isFrontChannel");
                handleFrontChannelLogoutRequest(facade);
                return true;
            }
            RefreshableOidcSecurityContext activeSession = (RefreshableOidcSecurityContext) facade.getSecurityContext();
            if (activeSession != null) {
                // we have an active session, should have received a GET logout request
                facade.getResponse().setStatus(HttpStatus.SC_METHOD_NOT_ALLOWED);
                facade.authenticationFailed();
                return true;
            }
            return false;
        }

        RefreshableOidcSecurityContext securityContext = getSecurityContext(facade);
        if (securityContext == null) {
            // no active session
            log.trace("tryLogout securityContext == null");
            return false;
        }

        if (isRpInitiatedLogoutPath(facade)) {
            log.trace("isRpInitiatedLogoutPath");
            redirectEndSessionEndpoint(facade);
            return true;
        }
        return false;
    }

    /*
        Removes the session from sessionsMarkedForInvalidation when present.
        @return true returned when session removed.  false returned when the seesion was not present
     */
    boolean removeIfSessionMarkedForInvalidation(OidcHttpFacade facade) {
        HttpScope session = facade.getScope(Scope.SESSION);
        if (session == null || ! session.exists()) {
            return false;
        }

        RefreshableOidcSecurityContext securityContext = (RefreshableOidcSecurityContext) session.getAttachment(OidcSecurityContext.class.getName());
        if (securityContext == null) {
            return false;
        }
        IDToken idToken = securityContext.getIDToken();

        if (idToken == null) {
            return false;
        }

        return sessionsMarkedForInvalidation.remove(getSessionKey(facade, idToken.getSid())) != null;
    }

    private void redirectEndSessionEndpoint(OidcHttpFacade facade) {
        RefreshableOidcSecurityContext securityContext = getSecurityContext(facade);
        OidcClientConfiguration clientConfiguration = securityContext.getOidcClientConfiguration();

        String logoutUri;

        try {
            URIBuilder redirectUriBuilder = new URIBuilder(clientConfiguration.getEndSessionEndpointUrl());
            if (securityContext.getIDTokenString() != null){
                redirectUriBuilder.addParameter(ID_TOKEN_HINT_PARAM, securityContext.getIDTokenString());
            }
            String postLogoutRedirectUri = clientConfiguration.getPostLogoutRedirectUri();
            if (postLogoutRedirectUri != null) {
                log.trace("post_logout_redirect_uri: " + postLogoutRedirectUri);
                redirectUriBuilder.addParameter(POST_LOGOUT_REDIRECT_URI_PARAM, postLogoutRedirectUri);
            }

            logoutUri = redirectUriBuilder.build().toString();
            log.trace("redirectEndSessionEndpoint path: " + logoutUri);
        } catch (URISyntaxException e) {
            throw log.unableToCreateEndSessionEndpointRequest(
                    clientConfiguration.getEndSessionEndpointUrl(), e.getMessage());
        }

        log.debugf("Invalidating local session during RP-initiated logout");
        facade.getTokenStore().logout(false);

        log.debugf("Sending redirect to the end_session_endpoint: %s", logoutUri);
        facade.getResponse().setStatus(HttpStatus.SC_MOVED_TEMPORARILY);
        facade.getResponse().setHeader(HttpConstants.LOCATION, logoutUri);
    }

    boolean tryBackChannelLogout(OidcHttpFacade facade) {
        if (isLogoutCallbackPath(facade)) {
            log.trace("isLogoutCallbackPath");
            if (isBackChannel(facade)) {
                log.trace("isBackChannel");
                handleBackChannelLogoutRequest(facade);
                return true;
            }
        }
        return false;
    }

    private void handleBackChannelLogoutRequest(OidcHttpFacade facade) {

        OidcClientConfiguration clientConfiguration = facade.getOidcClientConfiguration();
        String logoutToken = facade.getRequest().getFirstParam(LOGOUT_TOKEN_PARAM);
        TokenValidator.Builder tokenBuilder = TokenValidator.builder(clientConfiguration)
                .setSkipExpirationValidator();
        // Keycloak uses claim type "Logout".  Other OP's may be using "logout+jwt"
        // or a typ unique to it.
        String providerLogoutTokenType = (facade.getOidcClientConfiguration().getProviderJwtClaimsTyp() == null) ?
                KEYCLOCK_LOGOUT_TOKEN_TYPE : clientConfiguration.getProviderJwtClaimsTyp();
        TokenValidator tokenValidator = tokenBuilder.setTokenType(providerLogoutTokenType)
                .build();

        JwtClaims claims = null;
        Exception cause = null;
        try {
            claims = tokenValidator.parseAndVerifyLogoutToken(logoutToken);
        } catch (Exception expKeyclockClaims) {
            cause = expKeyclockClaims;
            if (expKeyclockClaims.getCause().getMessage().contains("ELY23054: Unexpected value for typ claim")) {
                log.warn("OpenID Provider claims typ " + providerLogoutTokenType
                        + " was not valid.  Trying typ "+ LOGOUT_JWT_TOKEN_TYPE);

                // check other OP's 'typ'
                tokenValidator = tokenBuilder.setTokenType(LOGOUT_JWT_TOKEN_TYPE)
                                .build();
                try {
                    claims = tokenValidator.verify(logoutToken);
                } catch (Exception expOtherProviderCliams) {
                    cause = expOtherProviderCliams;
                }
            }
            if (claims == null) {
                log.debugf("Unexpected error when verifying logout token", cause);
                facade.getResponse().setStatus(HttpStatus.SC_BAD_REQUEST);
                facade.authenticationFailed();
                return;
            }
        }

        if (!isLogoutSessionRequired(facade)) {
            log.warn(log.sidCanNotBeInferredFromLogoutToken());
            facade.getResponse().setStatus(HttpStatus.SC_BAD_REQUEST);
            facade.authenticationFailed();
            return;
        }

        String sessionId = claims.getClaimValueAsString(SID);
        String nonce = claims.getClaimValueAsString(NONCE);

        if (sessionId == null || nonce != null) {
            facade.getResponse().setStatus(HttpStatus.SC_BAD_REQUEST);
            facade.authenticationFailed();
            return;
        }

        log.debugf("Marking session for invalidation during back-channel logout");
        sessionsMarkedForInvalidation.put(getSessionKey(facade, sessionId), facade.getOidcClientConfiguration());
    }

    private String getSessionKey(OidcHttpFacade facade, String sessionId) {
        return facade.getOidcClientConfiguration().getClientId() + CLIENT_ID_SID_SEPARATOR + sessionId;
    }

    private void handleFrontChannelLogoutRequest(OidcHttpFacade facade) {
        if (isLogoutSessionRequired(facade)) {
            Request request = facade.getRequest();
            String sessionId = request.getQueryParamValue(SID);

            if (sessionId == null) {
                facade.getResponse().setStatus(HttpStatus.SC_BAD_REQUEST);
                facade.authenticationFailed();
                return;
            }

            RefreshableOidcSecurityContext context = getSecurityContext(facade);
            if (context == null) {
                return;
            }
            IDToken idToken = context.getIDToken();
            String issuer = request.getQueryParamValue(ISS);

            String validationFailure = null;
            if (idToken == null) {
                validationFailure = "ID token is missing";
            } else if (idToken.getSid() == null) {
                validationFailure = "ID token sid claim is missing";
            } else if (!sessionId.equals(idToken.getSid())) {
                validationFailure = String.format("request sid [%s] does not match ID token sid [%s]",
                        sessionId, idToken.getSid());
            } else if (issuer == null) {
                validationFailure = "iss query parameter is missing";
            } else if (idToken.getIssuer() == null) {
                validationFailure = "ID token issuer claim is missing";
            } else if (!idToken.getIssuer().equals(issuer)) {
                validationFailure = String.format("request iss [%s] does not match ID token issuer [%s]",
                        issuer, idToken.getIssuer());
            }
            if (validationFailure != null) {
                log.debugf("Front-channel logout validation failed: %s", validationFailure);
                facade.getResponse().setStatus(HttpStatus.SC_BAD_REQUEST);
                facade.authenticationFailed();
                return;
            }
        }

        log.debugf("Invalidating session during front-channel logout");
        facade.getTokenStore().logout(false);
    }

    private boolean isLogoutCallbackPath(OidcHttpFacade facade) {
        return matchesLogoutCallbackPath(facade.getRequest().getRelativePath(), getLogoutCallbackPath(facade));
    }

    /**
     * Returns whether the incoming request path matches the configured logout callback path.
     * The configured value may be a relative path (e.g. {@code /logout/callback}) or an absolute
     * {@code http}/{@code https} URI; only its path component is compared to the request path.
     */
    static boolean matchesLogoutCallbackPath(String requestRelativePath, String configuredLogoutCallbackPath) {
        String configuredPath = extractPathFromLogoutCallbackConfiguration(configuredLogoutCallbackPath);
        String requestPath = toComparablePath(requestRelativePath);
        if (configuredPath == null || requestPath == null) {
            return false;
        }
        return configuredPath.equals(requestPath);
    }

    static String extractPathFromLogoutCallbackConfiguration(String configuredLogoutCallbackPath) {
        if (configuredLogoutCallbackPath == null || configuredLogoutCallbackPath.isEmpty()) {
            return null;
        }
        String trimmed = configuredLogoutCallbackPath.trim();
        try {
            return toComparablePath(new URL(trimmed).getPath());
        } catch (MalformedURLException e) {
            if (OidcClientConfigurationBuilder.isValidRelativePath(trimmed)) {
                return toComparablePath(trimmed);
            }
            // Ignoring invalid logout-callback-path
            return null;
        }
    }

    private static String toComparablePath(String path) {
        if (path == null || path.isEmpty()) {
            return null;
        }
        return path.startsWith("/") ? path : "/" + path;
    }

    private boolean isRpInitiatedLogoutPath(OidcHttpFacade facade) {
        return matchesLogoutPath(facade.getRequest().getRelativePath(), getLogoutPath(facade));
    }

    /**
     * Returns whether the incoming request path matches the configured RP-initiated logout path.
     */
    static boolean matchesLogoutPath(String requestRelativePath, String configuredLogoutPath) {
        String requestPath = toComparablePath(requestRelativePath);
        String configuredPath = toComparablePath(configuredLogoutPath);
        if (configuredPath == null || requestPath == null) {
            return false;
        }
        return configuredPath.equals(requestPath);
    }

    private boolean isLogoutSessionRequired(OidcHttpFacade facade) {
        return facade.getOidcClientConfiguration().isLogoutSessionRequired();
    }

    private RefreshableOidcSecurityContext getSecurityContext(OidcHttpFacade facade) {
        RefreshableOidcSecurityContext securityContext = (RefreshableOidcSecurityContext) facade.getSecurityContext();

        if (securityContext == null) {
            facade.getResponse().setStatus(HttpStatus.SC_UNAUTHORIZED);
            facade.authenticationFailed();
            return null;
        }

        return securityContext;
    }

    private String getLogoutPath(OidcHttpFacade facade) {
        return facade.getOidcClientConfiguration().getLogoutPath();
    }
    private String getLogoutCallbackPath(OidcHttpFacade facade) {
        return facade.getOidcClientConfiguration().getLogoutCallbackPath();
    }

    private boolean isBackChannel(OidcHttpFacade facade) {
        return "post".equalsIgnoreCase(facade.getRequest().getMethod());
    }

    private boolean isFrontChannel(OidcHttpFacade facade) {
        return "get".equalsIgnoreCase(facade.getRequest().getMethod());
    }
}
