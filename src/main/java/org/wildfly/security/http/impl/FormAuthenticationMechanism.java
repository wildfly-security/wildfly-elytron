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
import static org.wildfly.security._private.ElytronMessages.log;
import static org.wildfly.security.http.HttpConstants.CONFIG_CONTEXT_PATH;
import static org.wildfly.security.http.HttpConstants.CONFIG_ERROR_PAGE;
import static org.wildfly.security.http.HttpConstants.CONFIG_LOGIN_PAGE;
import static org.wildfly.security.http.HttpConstants.CONFIG_POST_LOCATION;
import static org.wildfly.security.http.HttpConstants.FORM_NAME;
import static org.wildfly.security.http.HttpConstants.LOCATION;
import static org.wildfly.security.http.HttpConstants.POST;
import static org.wildfly.security.http.HttpConstants.SEE_OTHER;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
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
class FormAuthenticationMechanism extends UsernamePasswordAuthenticationMechanism {

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

    private IdentityCache createIdentityCache(HttpServerRequest request, boolean createSession) {
        return new IdentityCache() {
            @Override
            public void put(SecurityIdentity  identity) {
                HttpScope session = getSessionScope(request, createSession);

                if (!session.exists()) {
                    return;
                }

                session.setAttachment(CACHED_IDENTITY_KEY, new CachedIdentity(getMechanismName(), identity));
            }

            @Override
            public CachedIdentity get() {
                HttpScope session = getSessionScope(request, createSession);

                if (!session.exists()) {
                    return null;
                }

                return (CachedIdentity) session.getAttachment(CACHED_IDENTITY_KEY);
            }

            @Override
            public CachedIdentity remove() {
                HttpScope session = getSessionScope(request, createSession);

                if (!session.exists()) {
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

        if (username == null || password == null) {
            error(log.usernameOrPasswordMissing(), request);
            return;
        }

        char[] passwordChars = password.toCharArray();
        try {
            if (authenticate(null, username, passwordChars)) {
                if (authorize(username, request)) {
                    log.debugf("User %s authenticated successfully using FormAuthenticationMechanism!", username);
                    succeed();
                    HttpScope session = getSessionScope(request, true);
                    HttpServerMechanismsResponder responder = null;
                    if (session.exists()) {
                        String postAuthenticationPath;
                        String originalPath = session.getAttachment(LOCATION_KEY, String.class);
                        if (originalPath != null) {
                            postAuthenticationPath = originalPath;
                        } else {
                            String currentPath = request.getRequestURI().getPath();
                            postAuthenticationPath = currentPath.substring(0, currentPath.indexOf(DEFAULT_POST_LOCATION));
                        }
                        session.setAttachment(LOCATION_KEY, null);
                        responder = (response) -> sendRedirect(response, postAuthenticationPath);
                    }

                    request.authenticationComplete(responder);
                    return;
                } else {
                    failAndRedirectToErrorPage(request, username);
                    return;
                }

            } else {
                failAndRedirectToErrorPage(request, username);
                return;
            }
        } catch (IOException | UnsupportedCallbackException e) {
            throw new HttpAuthenticationException(e);
        } finally {
            fill(passwordChars, (char) 0x00);
        }
    }

    private boolean authorize(String username, HttpServerRequest request) throws HttpAuthenticationException {
        log.tracef("Authorizing username: [%s], Request URI: [%s], Context path: [%s]", username, request.getRequestURI(), this.contextPath);

        IdentityCache identityCache = createIdentityCache(request, true);
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
        if (log.isTraceEnabled()) {
            if (getSessionScope(request, false) != null) {
                log.tracef("Trying to re-authenticate session %s using FormAuthenticationMechanism. Request URI: [%s], Context path: [%s]",
                        getSessionScope(request, false).getID(), request.getRequestURI(), this.contextPath);
            } else {
                log.tracef("Unable to re-authenticate using FormAuthenticationMechanism. There is no session attached to the following request. " +
                        "Request URI: [%s], Context path: [%s]", request.getRequestURI(), this.contextPath);
            }
        }


        IdentityCache identityCache = createIdentityCache(request, false);
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
                request.authenticationComplete();
                return true;
            }
        }
        return false;
    }

    private void failAndRedirectToErrorPage(HttpServerRequest request, String username) throws IOException, UnsupportedCallbackException {
        IdentityCache identityCache = createIdentityCache(request, false);
        if (identityCache != null) {
            identityCache.remove();
        }
        fail();
        error(log.authorizationFailed(username, FORM_NAME), request);
    }

    void sendLogin(HttpServerRequest request, HttpServerResponse response) throws HttpAuthenticationException {
        // Save the current request.

        HttpScope session = getSessionScope(request, true);
        if (session.supportsAttachments()) {
            session.setAttachment(LOCATION_KEY, request.getRequestURI().getPath());
            request.suspendRequest();
        }

        sendPage(loginPage, request, response);
    }

    void sendPage(String page, HttpServerRequest request, HttpServerResponse response) throws HttpAuthenticationException {
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

        sendRedirect(response, contextPath + page);
    }

    private void sendRedirect(HttpServerResponse response, String location) {
        response.addResponseHeader(LOCATION, location);
        response.setStatusCode(SEE_OTHER);
    }

    private HttpScope getSessionScope(HttpServerRequest request, boolean createSession) {
        HttpScope scope = request.getScope(Scope.SESSION);

        if (!scope.exists() && createSession) {
            scope.create();
        }

        return scope;
    }
}
