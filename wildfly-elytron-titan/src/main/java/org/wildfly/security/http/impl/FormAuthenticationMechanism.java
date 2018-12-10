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
package org.wildfly.security.http.impl;

import static java.util.Arrays.fill;
import static org.wildfly.common.Assert.checkNotNullParam;
import static org.wildfly.security._private.ElytronMessages.httpForm;
import static org.wildfly.security.http.HttpConstants.CONFIG_CONTEXT_PATH;
import static org.wildfly.security.http.HttpConstants.CONFIG_ERROR_PAGE;
import static org.wildfly.security.http.HttpConstants.CONFIG_LOGIN_PAGE;
import static org.wildfly.security.http.HttpConstants.CONFIG_POST_LOCATION;
import static org.wildfly.security.http.HttpConstants.FORM_NAME;
import static org.wildfly.security.http.HttpConstants.FOUND;
import static org.wildfly.security.http.HttpConstants.HTTP;
import static org.wildfly.security.http.HttpConstants.HTTPS;
import static org.wildfly.security.http.HttpConstants.LOCATION;
import static org.wildfly.security.http.HttpConstants.POST;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.util.Map;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.wildfly.security.auth.callback.CachedIdentityAuthorizeCallback;
import org.wildfly.security.auth.server.SecurityIdentity;
import org.wildfly.security.cache.CachedIdentity;
import org.wildfly.security.cache.IdentityCache;
import org.wildfly.security.http.HttpAuthenticationException;
import org.wildfly.security.http.HttpScope;
import org.wildfly.security.http.HttpServerMechanismsResponder;
import org.wildfly.security.http.HttpServerRequest;
import org.wildfly.security.http.HttpServerResponse;
import org.wildfly.security.http.Scope;

/**
 * A generic FORM authentication mechanism which is usable in a number of different scenarios.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
final class FormAuthenticationMechanism extends UsernamePasswordAuthenticationMechanism {

    /*
     * These two could also be made configurable but defer until proven demand.
     */

    private static final String USERNAME = "j_username";
    private static final String PASSWORD = "j_password";

    private static final String LOCATION_KEY = FormAuthenticationMechanism.class.getName() + ".Location";
    private static final String CACHED_IDENTITY_KEY = FormAuthenticationMechanism.class.getName() + ".elytron-identity";

    private static final String DEFAULT_POST_LOCATION = "j_security_check";

    private final String contextPath;
    private final String loginPage;
    private final String errorPage;
    private final String postLocation;

    FormAuthenticationMechanism(final CallbackHandler callbackHandler, final Map<String, ?> properties) {
        super(checkNotNullParam("callbackHandler", callbackHandler));
        checkNotNullParam("properties", properties);

        String postLocation = (String) properties.get(CONFIG_POST_LOCATION);
        this.postLocation = postLocation != null ? postLocation : DEFAULT_POST_LOCATION;

        contextPath = properties.containsKey(CONFIG_CONTEXT_PATH) ? (String) properties.get(CONFIG_CONTEXT_PATH) : "";
        loginPage = (String) properties.get(CONFIG_LOGIN_PAGE);
        errorPage = (String) properties.get(CONFIG_ERROR_PAGE);
    }

    @Override
    public String getMechanismName() {
        return FORM_NAME;
    }

    /**
     * @see org.wildfly.security.http.HttpServerAuthenticationMechanism#evaluateRequest(org.wildfly.security.http.HttpServerRequest)
     */
    @Override
    public void evaluateRequest(final HttpServerRequest request) throws HttpAuthenticationException {
        // try to re-authenticate based on a previously cached identity
        if (attemptReAuthentication(request)) {
            return;
        }

        // Is current request an authentication attempt?
        if (POST.equals(request.getRequestMethod()) && request.getRequestURI().getPath().endsWith(postLocation)) {
            attemptAuthentication(request);
            return;
        }

        // Register challenger
        if (loginPage != null) {
            request.noAuthenticationInProgress((response) -> sendLogin(request, response));
        }
    }

    private IdentityCache createIdentityCache(HttpServerRequest request) {
        return new IdentityCache() {
            @Override
            public void put(SecurityIdentity  identity) {
                HttpScope session = getSessionScope(request, true);

                if (session == null || !session.exists()) {
                    return;
                }

                session.setAttachment(CACHED_IDENTITY_KEY, new CachedIdentity(getMechanismName(), identity));
            }

            @Override
            public CachedIdentity get() {
                HttpScope session = getSessionScope(request, false);

                if (session == null || !session.exists()) {
                    return null;
                }

                return (CachedIdentity) session.getAttachment(CACHED_IDENTITY_KEY);
            }

            @Override
            public CachedIdentity remove() {
                HttpScope session = getSessionScope(request, false);

                if (session == null || !session.exists()) {
                    return null;
                }

                CachedIdentity cachedIdentity = get();

                session.setAttachment(CACHED_IDENTITY_KEY, null);

                return cachedIdentity;
            }
        };
    }

    private void error(String message, HttpServerRequest request) {
        request.authenticationFailed(message, (response) -> sendPage(errorPage, request, response));
    }

    private void attemptAuthentication(HttpServerRequest request) throws HttpAuthenticationException {
        String username = request.getFirstParameterValue(USERNAME);
        String password = request.getFirstParameterValue(PASSWORD);

        if (username == null || username.length() == 0 || password == null) {
            error(httpForm.usernameOrPasswordMissing(), request);
            return;
        }

        char[] passwordChars = password.toCharArray();
        try {
            if (authenticate(null, username, passwordChars)) {
                IdentityCache identityCache = createIdentityCache(request);
                if (authorize(username, request, identityCache)) {
                    httpForm.debugf("User [%s] authenticated successfully", username);
                    succeed();

                    HttpScope session = getSessionScope(request, true);
                    HttpServerMechanismsResponder responder = null;
                    if (session != null && session.exists()) {
                        String postAuthenticationPath;
                        String originalPath = session.getAttachment(LOCATION_KEY, String.class);
                        if (originalPath != null) {
                            postAuthenticationPath = originalPath;
                            httpForm.tracef("User redirected to original path [%s]", postAuthenticationPath);
                        } else {
                            URI requestUri = request.getRequestURI();
                            String currentPath = requestUri.getPath();

                            StringBuilder sb = new StringBuilder();
                            String scheme = requestUri.getScheme();
                            sb.append(scheme);
                            sb.append("://");
                            sb.append(requestUri.getHost());
                            int port = requestUri.getPort();
                            if (appendPort(scheme, port)) {
                                sb.append(':').append(port);
                            }
                            sb.append(currentPath.substring(0, currentPath.indexOf(DEFAULT_POST_LOCATION)));

                            postAuthenticationPath = sb.toString();
                            httpForm.tracef("User redirected to default path [%s]", postAuthenticationPath);
                        }
                        session.setAttachment(LOCATION_KEY, null);
                        responder = (response) -> sendRedirect(response, postAuthenticationPath);
                    }

                    request.authenticationComplete(responder, identityCache::remove);
                    // no resumeRequest here, need to redirect first
                    return;
                } else {
                    httpForm.debugf("User [%s] authorization failed", username);
                    failAndRedirectToErrorPage(request, username);
                    return;
                }

            } else {
                httpForm.debugf("User [%s] authentication failed", username);
                failAndRedirectToErrorPage(request, username);
                return;
            }
        } catch (IOException | UnsupportedCallbackException e) {
            throw new HttpAuthenticationException(e);
        } finally {
            fill(passwordChars, (char) 0x00);
        }
    }

    private boolean authorize(String username, HttpServerRequest request, IdentityCache identityCache) throws HttpAuthenticationException {
        httpForm.tracef("Authorizing username: [%s], Request URI: [%s], Context path: [%s]", username, request.getRequestURI(), this.contextPath);

        if (identityCache != null) {
            CachedIdentityAuthorizeCallback authorizeCallback = new CachedIdentityAuthorizeCallback(username, identityCache);
            try {
                callbackHandler.handle(new Callback[]{authorizeCallback});
                return authorizeCallback.isAuthorized();
            } catch (IOException | UnsupportedCallbackException e) {
                throw new HttpAuthenticationException(e);
            }
        }
        return super.authorize(username);
    }

    private boolean attemptReAuthentication(HttpServerRequest request) throws HttpAuthenticationException {
        if (httpForm.isTraceEnabled()) {
            HttpScope sessionScope = getSessionScope(request, false);
            if (sessionScope != null && sessionScope.exists()) {
                httpForm.tracef("Trying to re-authenticate session %s. Request URI: [%s], Context path: [%s]",
                        sessionScope.getID(), request.getRequestURI(), this.contextPath);
            } else {
                httpForm.tracef("Trying to re-authenticate. There is no session attached to the following request. " +
                        "Request URI: [%s], Context path: [%s]", request.getRequestURI(), this.contextPath);
            }
        }

        IdentityCache identityCache = createIdentityCache(request);
        if (identityCache != null) {
            CachedIdentityAuthorizeCallback authorizeCallback = new CachedIdentityAuthorizeCallback(identityCache);
            try {
                callbackHandler.handle(new Callback[]{authorizeCallback});
            } catch (IOException | UnsupportedCallbackException e) {
                throw new HttpAuthenticationException(e);
            }
            if (authorizeCallback.isAuthorized()) {
                try {
                    succeed();
                } catch (IOException | UnsupportedCallbackException e) {
                    throw new HttpAuthenticationException(e);
                }
                request.authenticationComplete(null, identityCache::remove);
                request.resumeRequest();
                return true;
            }
        }
        return false;
    }

    private void failAndRedirectToErrorPage(HttpServerRequest request, String username) throws IOException, UnsupportedCallbackException {
        IdentityCache identityCache = createIdentityCache(request);
        if (identityCache != null) {
            identityCache.remove();
        }
        fail();
        error(httpForm.authorizationFailed(username), request);
    }

    private void sendLogin(HttpServerRequest request, HttpServerResponse response) throws HttpAuthenticationException {
        // Save the current request.
        URI requestURI = request.getRequestURI();
        HttpScope session = getSessionScope(request, true);
        if (session != null && session.supportsAttachments()) {
            StringBuilder sb = new StringBuilder();
            String scheme = requestURI.getScheme();
            sb.append(scheme);
            sb.append("://");
            sb.append(requestURI.getHost());
            int port = requestURI.getPort();
            if (appendPort(scheme, port)) {
                sb.append(':').append(port);
            }
            sb.append(requestURI.getPath());
            if(requestURI.getRawQuery() != null) {
                sb.append("?");
                sb.append(requestURI.getRawQuery());
            }
            if(requestURI.getRawFragment() != null) {
                sb.append("#");
                sb.append(requestURI.getRawFragment());
            }
            //TODO: we need to have some way up updating the jsessionid path parameter if the session ID changes
            //see UNDERTOW-958 for more details
            session.setAttachment(LOCATION_KEY, sb.toString());
            request.suspendRequest();
        }

        sendPage(loginPage, request, response);
    }

    private void sendPage(String page, HttpServerRequest request, HttpServerResponse response) throws HttpAuthenticationException {
        if (response.forward(page)) {
            return;
        }
        // Work out how and send the login page.
        HttpScope application = request.getScope(Scope.APPLICATION);
        if (application != null && application.supportsResources()) {
            try (InputStream pageStream = application.getResource(page)) {
                if (pageStream != null) {
                    OutputStream responseStream = response.getOutputStream();
                    if (responseStream != null) {
                        byte[] content = new byte[1024];
                        int length;
                        while ((length = pageStream.read(content)) > 0) {
                            responseStream.write(content, 0, length);
                        }

                        return;
                    }
                }
            } catch (IOException e) {
                throw new HttpAuthenticationException(e);
            }
        }

        URI requestURI = request.getRequestURI();
        StringBuilder sb = new StringBuilder();
        String scheme = requestURI.getScheme();
        sb.append(scheme);
        sb.append("://");
        sb.append(requestURI.getHost());
        int port = requestURI.getPort();
        if (appendPort(scheme, port)) {
            sb.append(':').append(port);
        }
        sb.append(contextPath);
        sb.append(page);
        sendRedirect(response, sb.toString());
    }

    private void sendRedirect(HttpServerResponse response, String location) {
        response.addResponseHeader(LOCATION, location);
        response.setStatusCode(FOUND);
    }

    private HttpScope getSessionScope(HttpServerRequest request, boolean createSession) {
        HttpScope scope = request.getScope(Scope.SESSION);

        if (scope != null &&!scope.exists() && createSession) {
            scope.create();
        }

        return scope;
    }

    private static boolean appendPort(final String scheme, final int port) {
        return port > -1 && ((HTTP.equalsIgnoreCase(scheme) && port != 80) || (HTTPS.equalsIgnoreCase(scheme) && port != 443));
    }
}
