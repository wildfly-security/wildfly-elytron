/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2015 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.http;

import static org.wildfly.security._private.ElytronMessages.log;
import static org.wildfly.security.http.HttpConstants.FORBIDDEN;
import static org.wildfly.security.http.HttpConstants.OK;
import static org.wildfly.security.http.HttpConstants.SECURITY_IDENTITY;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;
import java.util.function.Supplier;

import javax.net.ssl.SSLSession;

import org.wildfly.common.Assert;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.auth.server.SecurityIdentity;


/**
 * A HTTP based authenticator responsible for performing the authentication of the current request based on the policies of the
 * associated {@link SecurityDomain}.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class HttpAuthenticator {

    private final Supplier<List<HttpServerAuthenticationMechanism>> mechanismSupplier;
    private final HttpExchangeSpi httpExchangeSpi;
    private final boolean required;
    private final boolean ignoreOptionalFailures;
    private final Consumer<Runnable> logoutHandlerConsumer;
    private volatile boolean authenticated = false;

    private HttpAuthenticator(final Supplier<List<HttpServerAuthenticationMechanism>> mechanismSupplier, final HttpExchangeSpi httpExchangeSpi,
                              final boolean required, final boolean ignoreOptionalFailures, Consumer<Runnable> logoutHandlerConsumer) {
        this.mechanismSupplier = mechanismSupplier;
        this.httpExchangeSpi = httpExchangeSpi;
        this.required = required;
        this.ignoreOptionalFailures = ignoreOptionalFailures;
        this.logoutHandlerConsumer = logoutHandlerConsumer;
    }

    /**
     * Perform authentication for the request.
     *
     * @return {@code true} if the call should be allowed to continue within the web server, {@code false} if the call should be
     *         returning to the client.
     * @throws HttpAuthenticationException
     */
    public boolean authenticate() throws HttpAuthenticationException {
        return new AuthenticationExchange().authenticate();
    }

    private boolean isAuthenticated() {
        return authenticated;
    }

    /**
     * Construct and return a new {@code Builder} to configure and create an instance of {@code HttpAuthenticator}.
     *
     * @return a new {@code Builder} to configure and create an instance of {@code HttpAuthenticator}.
     */
    public static Builder builder() {
        return new Builder();
    }

    private class AuthenticationExchange implements HttpServerRequest, HttpServerResponse {

        private volatile HttpServerAuthenticationMechanism currentMechanism;

        private volatile boolean authenticationAttempted = false;
        private volatile int statusCode = -1;
        private volatile boolean statusCodeAllowed = false;
        private volatile List<HttpServerMechanismsResponder> responders;
        private volatile HttpServerMechanismsResponder successResponder;

        private boolean authenticate() throws HttpAuthenticationException {
            List<HttpServerAuthenticationMechanism> authenticationMechanisms = mechanismSupplier.get();
            if (required && authenticationMechanisms.size() == 0) {
                throw log.httpAuthenticationNoMechanisms();
            }
            responders = new ArrayList<>(authenticationMechanisms.size());
            boolean evaluationFailed = false;
            try {
                for (HttpServerAuthenticationMechanism nextMechanism : authenticationMechanisms) {
                    currentMechanism = nextMechanism;
                    try {
                        nextMechanism.evaluateRequest(this);
                    } catch (HttpAuthenticationException e) {
                        // Give all mechanisms an opportunity to succeed, where a mechanism fails due to mis-configuration or a transient error
                        // others may still be able to operate correctly.
                        evaluationFailed = true;
                        log.trace("Request evaluation for mechanism '%s' failed.", nextMechanism.getMechanismName(), e);
                    }

                    if (isAuthenticated()) {
                        if (successResponder != null) {
                            statusCodeAllowed = true;
                            successResponder.sendResponse(this);
                            if (statusCode > 0) {
                                httpExchangeSpi.setStatusCode(statusCode);
                                return false;
                            }
                        }
                        return true;
                    }
                }
                currentMechanism = null;

                if (required || (authenticationAttempted && ignoreOptionalFailures == false)) {
                    statusCodeAllowed = true;
                    if (responders.size() > 0) {
                        boolean atLeastOneChallenge = false;
                        for (HttpServerMechanismsResponder responder : responders) {
                            try {
                                responder.sendResponse(this);
                                atLeastOneChallenge = true;
                            } catch (HttpAuthenticationException e) {
                                log.trace("HTTP authentication mechanism unable to send challenge.", e);
                            }
                        }
                        if (atLeastOneChallenge == false) {
                            throw log.httpAuthenticationNoSuccessfulResponder();
                        }
                        if (statusCode > 0) {
                            httpExchangeSpi.setStatusCode(statusCode);
                        } else {
                            httpExchangeSpi.setStatusCode(OK);
                        }
                    } else {
                        if (evaluationFailed) {
                            throw log.httpAuthenticationFailedEvaluatingRequest();
                        }
                        httpExchangeSpi.setStatusCode(FORBIDDEN);
                    }
                    return false;
                }

                // If authentication was required it should have been picked up in the previous block.
                return true;
            } finally {
                authenticationMechanisms.forEach(m -> m.dispose());
            }
        }

        @Override
        public List<String> getRequestHeaderValues(String headerName) {
            return httpExchangeSpi.getRequestHeaderValues(headerName);
        }

        @Override
        public String getFirstRequestHeaderValue(String headerName) {
            return httpExchangeSpi.getFirstRequestHeaderValue(headerName);
        }

        @Override
        public SSLSession getSSLSession() {
            return httpExchangeSpi.getSSLSession();
        }

        @Override
        public Certificate[] getPeerCertificates() {
            return httpExchangeSpi.getPeerCertificates(required);
        }

        @Override
        public HttpScope getScope(Scope scope) {
            return httpExchangeSpi.getScope(scope);
        }

        @Override
        public Collection<String> getScopeIds(Scope scope) {
            return httpExchangeSpi.getScopeIds(scope);
        }

        @Override
        public HttpScope getScope(Scope scope, String id) {
            return httpExchangeSpi.getScope(scope, id);
        }

        @Override
        public void noAuthenticationInProgress(HttpServerMechanismsResponder responder) {
            if (responder != null) {
                responders.add(responder);
            }
        }

        @Override
        public void authenticationInProgress(HttpServerMechanismsResponder responder) {
            authenticationAttempted = true;
            if (responder != null) {
                responders.add(responder);
            }
        }

        @Override
        public void authenticationComplete(HttpServerMechanismsResponder responder) {
            authenticated = true;
            httpExchangeSpi.authenticationComplete(
                    currentMechanism.getNegotiationProperty(SECURITY_IDENTITY, SecurityIdentity.class),
                    currentMechanism.getMechanismName());
            successResponder = responder;
        }

        @Override
        public void authenticationComplete(HttpServerMechanismsResponder responder, Runnable logoutHandler) {
            authenticationComplete(responder);
            if (logoutHandlerConsumer != null) {
                logoutHandlerConsumer.accept(logoutHandler);
            }
        }

        @Override
        public void authenticationFailed(String message, HttpServerMechanismsResponder responder) {
            authenticationAttempted = true;
            httpExchangeSpi.authenticationFailed(message, currentMechanism.getMechanismName());
            if (responder != null) {
                responders.add(responder);
            }
        }

        @Override
        public void badRequest(HttpAuthenticationException failure, HttpServerMechanismsResponder responder) {
            authenticationAttempted = true;
            httpExchangeSpi.badRequest(failure, currentMechanism.getMechanismName());
            if (responder != null) {
                responders.add(responder);
            }
        }

        @Override
        public String getRequestMethod() {
            return httpExchangeSpi.getRequestMethod();
        }

        @Override
        public URI getRequestURI() {
            return httpExchangeSpi.getRequestURI();
        }

        @Override
        public String getRequestPath() {
            return httpExchangeSpi.getRequestPath();
        }

        @Override
        public Map<String, List<String>> getParameters() {
            return httpExchangeSpi.getRequestParameters();
        }

        @Override
        public Set<String> getParameterNames() {
            return httpExchangeSpi.getRequestParameterNames();
        }

        @Override
        public List<String> getParameterValues(String name) {
            return httpExchangeSpi.getRequestParameterValues(name);
        }

        @Override
        public String getFirstParameterValue(String name) {
            return httpExchangeSpi.getFirstRequestParameterValue(name);
        }

        @Override
        public List<HttpServerCookie> getCookies() {
            return httpExchangeSpi.getCookies();
        }

        @Override
        public InputStream getInputStream() {
            return httpExchangeSpi.getRequestInputStream();
        }

        @Override
        public InetSocketAddress getSourceAddress() {
            return httpExchangeSpi.getSourceAddress();
        }

        @Override
        public void addResponseHeader(String headerName, String headerValue) {
            httpExchangeSpi.addResponseHeader(headerName, headerValue);
        }

        @Override
        public void setStatusCode(int statusCode) {
            if (statusCodeAllowed == false) {
                throw log.statusCodeNotNow();
            }

            this.statusCode = statusCode;
        }

        @Override
        public OutputStream getOutputStream() {
            return httpExchangeSpi.getResponseOutputStream();
        }

        @Override
        public void setResponseCookie(HttpServerCookie cookie) {
            httpExchangeSpi.setResponseCookie(cookie);
        }

        @Override
        public boolean forward(String path) {
            int statusCode = httpExchangeSpi.forward(path); // starts response, any following statusCode setting will be ignored
            if (statusCode > 0) {
                setStatusCode(statusCode);

                return true;
            }

            return false;
        }

        @Override
        public boolean suspendRequest() {
            return httpExchangeSpi.suspendRequest();
        }

        @Override
        public boolean resumeRequest() {
            return httpExchangeSpi.resumeRequest();
        }

    }

    /**
     * A {@code Builder} to configure and create an instance of {@code HttpAuthenticator}.
     */
    public static class Builder {

        private Supplier<List<HttpServerAuthenticationMechanism>> mechanismSupplier;
        private HttpExchangeSpi httpExchangeSpi;
        private boolean required;
        private boolean ignoreOptionalFailures;
        private Consumer<Runnable> logoutHandlerConsumer;

        Builder() {
        }

        /**
         * Set the {@link Supplier<List<HttpServerAuthenticationMechanism>>} to use to obtain the actual {@link HttpServerAuthenticationMechanism} instances based
         * on the configured policy.
         *
         * @param mechanismSupplier the {@link Supplier<List<HttpServerAuthenticationMechanism>>} with the configured authentication policy.
         * @return the {@link Builder} to allow method call chaining.
         */
        public Builder setMechanismSupplier(Supplier<List<HttpServerAuthenticationMechanism>> mechanismSupplier) {
            this.mechanismSupplier = mechanismSupplier;

            return this;
        }

        /**
         * Set the {@link HttpExchangeSpi} instance for the current request to allow integration with the Elytron APIs.
         *
         * @param httpExchangeSpi the {@link HttpExchangeSpi} instance for the current request
         * @return the {@link Builder} to allow method call chaining.
         */
        public Builder setHttpExchangeSpi(final HttpExchangeSpi httpExchangeSpi) {
            this.httpExchangeSpi = httpExchangeSpi;

            return this;
        }


        /**
         * Sets if authentication is required for the current request, if not required mechanisms will be called to be given the
         * opportunity to authenticate
         *
         * @param required is authentication required for the current request?
         * @return the {@link Builder} to allow method call chaining.
         */
        public Builder setRequired(final boolean required) {
            this.required = required;

            return this;
        }

        /**
         * Where authentication is not required but is still attempted a failure of an authentication mechanism will cause the
         * challenges to be sent and the current request returned to the client, setting this value to true will allow the
         * failure to be ignored.
         *
         * This setting has no effect when required is set to {@code true}, in that case all failures will result in a client
         *
         * @param ignoreOptionalFailures should mechanism failures be ignored if authentication is optional.
         * @return the {@link Builder} to allow method call chaining.
         */
        public Builder setIgnoreOptionalFailures(final boolean ignoreOptionalFailures) {
            this.ignoreOptionalFailures = ignoreOptionalFailures;

            return this;
        }

        /**
         * <p>A {@link Consumer} responsible for registering a {@link Runnable} emitted by one of the mechanisms during the evaluation
         * of a request and representing some action to be taken during logout.
         *
         * <p>This method is mainly targeted for programmatic logout where logout requests are send by the application after the
         * authentication. Although, integration code is free to register the logout handler whatever they want in order to support
         * different logout scenarios.
         *
         * @param logoutHandlerConsumer the consumer responsible for registering the logout handler (not {@code null})
         * @return the {@link Builder} to allow method call chaining.
         */
        public Builder registerLogoutHandler(Consumer<Runnable> logoutHandlerConsumer) {
            this.logoutHandlerConsumer = Assert.checkNotNullParam("logoutHandlerConsumer", logoutHandlerConsumer);
            return this;
        }

        /**
         * Build the new {@code HttpAuthenticator} instance.
         *
         * @return the new {@code HttpAuthenticator} instance.
         */
        public HttpAuthenticator build() {
            return new HttpAuthenticator(mechanismSupplier, httpExchangeSpi, required, ignoreOptionalFailures, logoutHandlerConsumer);
        }

    }

}
