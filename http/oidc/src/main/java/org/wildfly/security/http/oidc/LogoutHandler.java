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
import static org.wildfly.security.http.oidc.ElytronMessages.log;

import java.net.URISyntaxException;
import java.util.LinkedHashMap;
import java.util.Map;

import org.apache.http.HttpStatus;
import org.apache.http.client.utils.URIBuilder;
import org.jose4j.jwt.JwtClaims;
import org.wildfly.security.http.HttpConstants;
import org.wildfly.security.http.oidc.OidcHttpFacade.Request;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
final class LogoutHandler {

    public static final String POST_LOGOUT_REDIRECT_URI_PARAM = "post_logout_redirect_uri";
    public static final String ID_TOKEN_HINT_PARAM = "id_token_hint";
    private static final String LOGOUT_TOKEN_PARAM = "logout_token";
    private static final String LOGOUT_TOKEN_TYPE = "Logout";
    public static final String SID = "sid";
    public static final String ISS = "iss";

    /**
     * A bounded map to store sessions marked for invalidation after receiving logout requests through the back-channel
     */
    private Map<String, OidcClientConfiguration> sessionsMarkedForInvalidation = synchronizedMap(new LinkedHashMap<String, OidcClientConfiguration>(16, 0.75f, true) {
        @Override
        protected boolean removeEldestEntry(Map.Entry<String, OidcClientConfiguration> eldest) {
            boolean remove = sessionsMarkedForInvalidation.size() > eldest.getValue().getLogoutSessionWaitingLimit();

            if (remove) {
                log.debugf("Limit [%s] reached for sessions waiting [%s] for logout", eldest.getValue().getLogoutSessionWaitingLimit(), sessionsMarkedForInvalidation.size());
            }

            return remove;
        }
    });

    boolean tryLogout(OidcHttpFacade facade) {
        RefreshableOidcSecurityContext securityContext = getSecurityContext(facade);

        if (securityContext == null) {
            // no active session
            return false;
        }

        if (isSessionMarkedForInvalidation(facade)) {
            // session marked for invalidation, invalidate it
            log.debug("Invalidating pending logout session");
            facade.getTokenStore().logout(false);
            return true;
        }

        if (isRpInitiatedLogoutPath(facade)) {
            redirectEndSessionEndpoint(facade);
            return true;
        }

        if (isLogoutCallbackPath(facade)) {
            handleLogoutRequest(facade);
            return true;
        }

        return false;
    }

    private boolean isSessionMarkedForInvalidation(OidcHttpFacade facade) {
        RefreshableOidcSecurityContext securityContext = getSecurityContext(facade);
        IDToken idToken = securityContext.getIDToken();

        if (idToken == null) {
            return false;
        }

        return sessionsMarkedForInvalidation.remove(idToken.getSid()) != null;
    }

    private void redirectEndSessionEndpoint(OidcHttpFacade facade) {
        RefreshableOidcSecurityContext securityContext = getSecurityContext(facade);
        OidcClientConfiguration clientConfiguration = securityContext.getOidcClientConfiguration();

        String logoutUri;

        try {
            URIBuilder redirectUriBuilder = new URIBuilder(clientConfiguration.getEndSessionEndpointUrl())
                    .addParameter(ID_TOKEN_HINT_PARAM, securityContext.getIDTokenString());
            String postLogoutPath = clientConfiguration.getPostLogoutPath();
            if (postLogoutPath != null) {
                redirectUriBuilder.addParameter(POST_LOGOUT_REDIRECT_URI_PARAM,
                        getRedirectUri(facade) + postLogoutPath);
            }

            logoutUri = redirectUriBuilder.build().toString();
        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        }

        log.debugf("Sending redirect to the end_session_endpoint: %s", logoutUri);
        facade.getResponse().setStatus(HttpStatus.SC_MOVED_TEMPORARILY);
        facade.getResponse().setHeader(HttpConstants.LOCATION, logoutUri);
    }

    private void handleLogoutRequest(OidcHttpFacade facade) {
        if (isFrontChannel(facade)) {
            handleFrontChannelLogoutRequest(facade);
        } else if (isBackChannel(facade)) {
            handleBackChannelLogoutRequest(facade);
        } else {
            // logout requests should arrive either as a HTTP GET or POST
            facade.getResponse().setStatus(HttpStatus.SC_METHOD_NOT_ALLOWED);
            facade.authenticationFailed();
        }
    }

    private void handleBackChannelLogoutRequest(OidcHttpFacade facade) {
        RefreshableOidcSecurityContext securityContext = getSecurityContext(facade);
        String logoutToken = facade.getRequest().getFirstParam(LOGOUT_TOKEN_PARAM);
        TokenValidator tokenValidator = TokenValidator.builder(facade.getOidcClientConfiguration())
                .setSkipExpirationValidator()
                .setTokenType(LOGOUT_TOKEN_TYPE)
                .build();
        JwtClaims claims;

        try {
            claims = tokenValidator.verify(logoutToken);
        } catch (Exception cause) {
            log.debug("Unexpected error when verifying logout token", cause);
            facade.getResponse().setStatus(HttpStatus.SC_BAD_REQUEST);
            facade.authenticationFailed();
            return;
        }

        if (!isSessionRequiredOnLogout(facade)) {
            log.warn("Back-channel logout request received but can not infer sid from logout token to mark it for invalidation");
            facade.getResponse().setStatus(HttpStatus.SC_BAD_REQUEST);
            facade.authenticationFailed();
            return;
        }

        String sessionId = claims.getClaimValueAsString(SID);

        if (sessionId == null) {
            facade.getResponse().setStatus(HttpStatus.SC_BAD_REQUEST);
            facade.authenticationFailed();
            return;
        }

        log.debug("Marking session for invalidation during back-channel logout");
        sessionsMarkedForInvalidation.put(sessionId, securityContext.getOidcClientConfiguration());
    }

    private void handleFrontChannelLogoutRequest(OidcHttpFacade facade) {
        if (isSessionRequiredOnLogout(facade)) {
            Request request = facade.getRequest();
            String sessionId = request.getQueryParamValue(SID);

            if (sessionId == null) {
                facade.getResponse().setStatus(HttpStatus.SC_BAD_REQUEST);
                facade.authenticationFailed();
                return;
            }

            RefreshableOidcSecurityContext context = getSecurityContext(facade);
            IDToken idToken = context.getIDToken();
            String issuer = request.getQueryParamValue(ISS);

            if (idToken == null || !sessionId.equals(idToken.getSid()) || !idToken.getIssuer().equals(issuer)) {
                facade.getResponse().setStatus(HttpStatus.SC_BAD_REQUEST);
                facade.authenticationFailed();
                return;
            }
        }

        log.debug("Invalidating session during front-channel logout");
        facade.getTokenStore().logout(false);
    }

    private String getRedirectUri(OidcHttpFacade facade) {
        String uri = facade.getRequest().getURI();

        if (uri.indexOf('?') != -1) {
            uri = uri.substring(0, uri.indexOf('?'));
        }
        int logoutPathIndex = uri.indexOf(getLogoutPath(facade));

        if (logoutPathIndex != -1) {
            uri = uri.substring(0, logoutPathIndex);
        }

        return uri;
    }

    private boolean isLogoutCallbackPath(OidcHttpFacade facade) {
        String path = facade.getRequest().getRelativePath();
        String xx = getLogoutCallbackPath(facade); // rls debug only
        return path.endsWith(getLogoutCallbackPath(facade));
    }

    private boolean isRpInitiatedLogoutPath(OidcHttpFacade facade) {
        String path = facade.getRequest().getRelativePath();
        return path.endsWith(getLogoutPath(facade));
    }

    private boolean isSessionRequiredOnLogout(OidcHttpFacade facade) {
        return getOidcClientConfiguration(facade).isSessionRequiredOnLogout();
    }

    private OidcClientConfiguration getOidcClientConfiguration(OidcHttpFacade facade) {
        RefreshableOidcSecurityContext securityContext = getSecurityContext(facade);

        if (securityContext == null) {
            return null;
        }

        return securityContext.getOidcClientConfiguration();
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
        return getOidcClientConfiguration(facade).getLogoutPath();
    }
    private String getLogoutCallbackPath(OidcHttpFacade facade) {
        return getOidcClientConfiguration(facade).getLogoutCallbackPath();
    }

    private boolean isBackChannel(OidcHttpFacade facade) {
        return "post".equalsIgnoreCase(facade.getRequest().getMethod());
    }

    private boolean isFrontChannel(OidcHttpFacade facade) {
        return "get".equalsIgnoreCase(facade.getRequest().getMethod());
    }
}
