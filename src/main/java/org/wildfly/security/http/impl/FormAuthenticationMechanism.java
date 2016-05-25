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

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

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
    private static final String IDENTITY_CREDENTIAL_KEY = FormAuthenticationMechanism.class.getName() + ".Identity-Credential";

    private static final String DEFAULT_POST_LOCATION = "j_security_check";

    private final String contextPath;
    private final String loginPage;
    private final String errorPage;
    private final String postLocation;

    FormAuthenticationMechanism(final CallbackHandler callbackHandler, final Map<String, ?> properties) {
        super(checkNotNullParam("callbackHandler", callbackHandler), null);
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

        // Do we have a cached identity?
        HttpScope session = request.getScope(Scope.SESSION);
        if (session != null) {
            FormIdentityCredentials identityCredentials = session.getAttachment(IDENTITY_CREDENTIAL_KEY, FormIdentityCredentials.class);
            if (identityCredentials != null) {
                String username = identityCredentials.getUsername();
                char[] password = identityCredentials.getPassword();
                try {
                    if (authenticate(username, password) && authorize(username)) {
                        succeed();
                        request.authenticationComplete();

                        return;
                    } else {
                        identityCredentials.dispose();
                        session.setAttachment(IDENTITY_CREDENTIAL_KEY, null);
                    }
                } catch (IOException | UnsupportedCallbackException e) {
                    throw new HttpAuthenticationException(e);
                } finally {
                    fill(password, (char) 0x00);
                }
            }
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
            if (authenticate(username, passwordChars)) {
                if (authorize(username)) {
                    succeed();

                    HttpScope session = request.getScope(Scope.SESSION);
                    HttpServerMechanismsResponder responder = null;
                    if (session != null) {
                        session.setAttachment(IDENTITY_CREDENTIAL_KEY, new FormIdentityCredentials(username, password.toCharArray()));

                        String originalPath = session.getAttachment(LOCATION_KEY, String.class);
                        if (originalPath != null) {
                            session.setAttachment(LOCATION_KEY, null);
                            responder = (response) -> sendRedirect(response, originalPath);
                        }
                    }

                    request.authenticationComplete(responder);

                    return;
                } else {
                    fail();

                    error(log.authorizationFailed(username, FORM_NAME), request);
                    return;
                }

            } else {
                fail();

                error(log.authenticationFailed(username, FORM_NAME), request);
                return;
            }
        } catch (IOException | UnsupportedCallbackException e) {
            throw new HttpAuthenticationException(e);
        } finally {
            fill(passwordChars, (char) 0x00);
        }
    }

    void sendLogin(HttpServerRequest request, HttpServerResponse response) throws HttpAuthenticationException {
        // Save the current request.

        HttpScope session = request.getScope(Scope.SESSION);
        if (session != null && session.supportsAttachments()) {
            session.setAttachment(LOCATION_KEY, request.getRequestURI().getPath());
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

    /*
     * Suspend / Resume Options
     *
     * 1 - Cache URL only and redirect as GET request.
     * 2 - Delegate suspend / resume to HTTP server - i.e. cache the whole request.
     * 3 - Ignore address of security intercept and rederect to pre-defined location after auth.
     */

    /*
     * Challenge Options
     *
     * 1 - Redirect to login page / error page.
     * 2 - Access resource and serve directly.
     * 3 - Internally forward request to page.
     */

    final class FormIdentityCredentials {
        private final String username;
        private final char[] password;

        FormIdentityCredentials(String username, char[] password) {
            this.username = username;
            this.password = new char[password.length];
            System.arraycopy(password, 0, this.password, 0, password.length);
        }

        String getUsername() {
            return username;
        }

        char[] getPassword() {
            char[] password = new char[this.password.length];
            System.arraycopy(this.password, 0, password, 0, this.password.length);

            return password;
        }

        void dispose() {
            fill(password, (char) 0x00);
        }

    }
}
