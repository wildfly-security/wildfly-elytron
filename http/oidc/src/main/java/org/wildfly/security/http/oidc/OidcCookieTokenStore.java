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

import static org.wildfly.security.http.oidc.ElytronMessages.log;
import static org.wildfly.security.http.oidc.Oidc.OIDC_STATE_COOKIE;
import static org.wildfly.security.http.oidc.Oidc.checkCachedAccountMatchesRequest;
import static org.wildfly.security.http.oidc.Oidc.SESSION_RANDOM_VALUE;

import java.net.URISyntaxException;
import java.util.List;

import org.apache.http.client.utils.URIBuilder;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.wildfly.security.http.HttpScope;
import org.wildfly.security.http.Scope;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class OidcCookieTokenStore implements OidcTokenStore {

    private final OidcHttpFacade httpFacade;
    private static final String DELIM = "###";
    private static final String LEGACY_DELIM = "___";
    private static final int EXPECTED_NUM_TOKENS = 3;
    private static final int ACCESS_TOKEN_INDEX = 0;
    private static final int ID_TOKEN_INDEX = 1;
    private static final int REFRESH_TOKEN_INDEX = 2;

    public OidcCookieTokenStore(OidcHttpFacade httpFacade) {
        this.httpFacade = httpFacade;
    }

    @Override
    public void checkCurrentToken() {
        OidcClientConfiguration deployment = httpFacade.getOidcClientConfiguration();
        OidcPrincipal<RefreshableOidcSecurityContext> principal = OidcCookieTokenStore.getPrincipalFromCookie(deployment, httpFacade, this);
        if (principal == null) {
            return;
        }
        RefreshableOidcSecurityContext securityContext = principal.getOidcSecurityContext();
        if (securityContext.isActive() && ! securityContext.getOidcClientConfiguration().isAlwaysRefreshToken()) return;
        // FYI: A refresh requires same scope, so same roles will be set.  Otherwise, refresh will fail and token will
        // not be updated
        boolean success = securityContext.refreshToken(false);
        if (success && securityContext.isActive()) return;
        saveAccountInfo(new OidcAccount(principal));
    }

    @Override
    public boolean isCached(RequestAuthenticator authenticator) {
        OidcClientConfiguration deployment = httpFacade.getOidcClientConfiguration();
        OidcPrincipal<RefreshableOidcSecurityContext> principal = OidcCookieTokenStore.getPrincipalFromCookie(deployment, httpFacade, this);
        if (principal == null) {
            log.debug("Account was not in cookie or was invalid, returning null");
            return false;
        }
        OidcAccount account = new OidcAccount(principal);
        if (! checkCachedAccountMatchesRequest(account, deployment)) {
            return false;
        }

        boolean active = account.checkActive();
        if (! active) {
            active = account.tryRefresh();
        }
        if (active) {
            log.debug("Cached account found");
            restoreRequest();
            httpFacade.authenticationComplete(account, true);
            return true;
        } else {
            log.debug("Account was not active, removing cookie and returning false");
            removeCookie(deployment, httpFacade);
            return false;
        }
    }

    @Override
    public void saveAccountInfo(OidcAccount account) {
        RefreshableOidcSecurityContext secContext = account.getOidcSecurityContext();
        OidcCookieTokenStore.setTokenCookie(this.httpFacade.getOidcClientConfiguration(), this.httpFacade, secContext);
        HttpScope exchange = this.httpFacade.getScope(Scope.EXCHANGE);
        exchange.registerForNotification(httpServerScopes -> logout());
        exchange.setAttachment(OidcAccount.class.getName(), account);
        exchange.setAttachment(OidcSecurityContext.class.getName(), account.getOidcSecurityContext());
        restoreRequest();
    }

    @Override
    public void logout() {
        logout(false);
    }

    @Override
    public void refreshCallback(RefreshableOidcSecurityContext securityContext) {
        OidcCookieTokenStore.setTokenCookie(this.httpFacade.getOidcClientConfiguration(), httpFacade, securityContext);
    }

    @Override
    public void saveRequest() {

    }

    @Override
    public boolean restoreRequest() {
        return false;
    }

    @Override
    public void logout(boolean glo) {
        OidcPrincipal<RefreshableOidcSecurityContext> principal = OidcCookieTokenStore.getPrincipalFromCookie(httpFacade.getOidcClientConfiguration(), httpFacade, this);
        if (principal == null) {
            return;
        }
        OidcCookieTokenStore.removeCookie(httpFacade.getOidcClientConfiguration(), httpFacade);
        if (glo) {
            OidcSecurityContext securityContext = principal.getOidcSecurityContext();
            if (securityContext == null) {
                return;
            }
            OidcClientConfiguration deployment = httpFacade.getOidcClientConfiguration();
            if (! deployment.isBearerOnly() && securityContext instanceof RefreshableOidcSecurityContext) {
                ((RefreshableOidcSecurityContext) securityContext).logout(deployment);
            }
        }
    }

    @Override
    public void logoutAll() {
        //no-op
    }

    @Override
    public void logoutHttpSessions(List<String> ids) {
        //no-op
    }

    public static void removeCookie(OidcClientConfiguration deployment, OidcHttpFacade facade) {
        String cookiePath = getCookiePath(deployment, facade);
        facade.getResponse().resetCookie(OIDC_STATE_COOKIE, cookiePath);
    }

    public static void setTokenCookie(OidcClientConfiguration deployment, OidcHttpFacade facade, RefreshableOidcSecurityContext session) {
        log.debugf("Set new %s cookie now", OIDC_STATE_COOKIE);
        String accessToken = session.getTokenString();
        String idToken = session.getIDTokenString();
        String refreshToken = session.getRefreshToken();
        String cookie = new StringBuilder(accessToken).append(DELIM)
                .append(idToken).append(DELIM)
                .append(refreshToken).toString();
        String cookiePath = getCookiePath(deployment, facade);
        facade.getResponse().setCookie(OIDC_STATE_COOKIE, cookie, cookiePath, null, -1, deployment.getSSLRequired().isRequired(facade.getRequest().getRemoteAddr()), true);
    }

    static String getCookiePath(OidcClientConfiguration deployment, OidcHttpFacade facade) {
        String path = deployment.getOidcStateCookiePath() == null ? "" : deployment.getOidcStateCookiePath().trim();
        if (path.startsWith("/")) {
            return path;
        }
        String contextPath = getContextPath(facade);
        StringBuilder cookiePath = new StringBuilder(contextPath);
        if (!contextPath.endsWith("/") && !path.isEmpty()) {
            cookiePath.append("/");
        }
        return cookiePath.append(path).toString();
    }

    static String getContextPath(OidcHttpFacade facade) {
        String uri = facade.getRequest().getURI();
        String path = null;
        try {
            path = new URIBuilder(uri).build().getPath();
        } catch (URISyntaxException e) {
            throw log.invalidUri(uri);
        }
        if (path == null || path.isEmpty()) {
            return "/";
        }
        int index = path.indexOf("/", 1);
        return index == -1 ? path : path.substring(0, index);
    }

    public static OidcPrincipal<RefreshableOidcSecurityContext> getPrincipalFromCookie(OidcClientConfiguration deployment, OidcHttpFacade facade, OidcCookieTokenStore tokenStore) {
        OidcHttpFacade.Cookie cookie = facade.getRequest().getCookie(OIDC_STATE_COOKIE);
        if (cookie == null) {
            log.debug("OIDC state cookie not found in current request");
            return null;
        }
        String cookieVal = cookie.getValue();
        String[] tokens = cookieVal.split(DELIM);
        if (tokens.length != EXPECTED_NUM_TOKENS) {
            // Cookies set by older versions of wildfly-elytron use a different token delimiter. Since clients may
            // still send such cookies we fall back to the old delimiter to avoid discarding valid tokens:
            tokens = cookieVal.split(LEGACY_DELIM);
        }
        if (tokens.length != EXPECTED_NUM_TOKENS) {
            log.warnf("Invalid format of %s cookie. Count of tokens: %s, expected %s", OIDC_STATE_COOKIE, tokens.length, EXPECTED_NUM_TOKENS);
            log.debugf("Value of %s cookie is: %s", OIDC_STATE_COOKIE, cookieVal);
            return null;
        }
        String accessTokenString = tokens[ACCESS_TOKEN_INDEX];
        String idTokenString = tokens[ID_TOKEN_INDEX];
        String refreshTokenString = tokens[REFRESH_TOKEN_INDEX];

        try {
            AccessToken accessToken = new AccessToken(new JwtConsumerBuilder().setSkipSignatureVerification().setSkipAllValidators().build().processToClaims(accessTokenString));
            IDToken idToken = null;
            if (idTokenString != null && idTokenString.length() > 0) {
                idToken = new IDToken(new JwtConsumerBuilder().setSkipSignatureVerification().setSkipAllValidators().build().processToClaims(idTokenString));
            }
            log.debug("Token obtained from cookie");
            RefreshableOidcSecurityContext secContext = new RefreshableOidcSecurityContext(deployment, facade.getRequest().getCookie(SESSION_RANDOM_VALUE), tokenStore, accessTokenString, accessToken, idTokenString, idToken, refreshTokenString);
            return new OidcPrincipal<>(idToken.getPrincipalName(deployment), secContext);
        } catch (InvalidJwtException e) {
            log.failedToParseTokenFromCookie(e);
            return null;
        }
    }
}


