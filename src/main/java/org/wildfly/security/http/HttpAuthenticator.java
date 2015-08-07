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

import java.util.List;
import java.util.function.Supplier;

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
    private volatile boolean authenticated = false;

    private HttpAuthenticator(final Supplier<List<HttpServerAuthenticationMechanism>> mechanismSupplier, final HttpExchangeSpi httpExchangeSpi,
            final boolean required, final boolean ignoreOptionalFailures) {
        this.mechanismSupplier = mechanismSupplier;
        this.httpExchangeSpi = httpExchangeSpi;
        this.required = required;
        this.ignoreOptionalFailures = ignoreOptionalFailures;
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

    public static Builder builder() {
        return new Builder();
    }

    private class AuthenticationExchange extends HttpServerExchange {

        private volatile HttpServerAuthenticationMechanism currentMechanism;

        private volatile int responseCode = -1;
        private volatile boolean responseCodeAllowed = false;

        /**
         * @param httpExchangeSpi
         */
        AuthenticationExchange() {
            super(httpExchangeSpi);
        }

        private boolean authenticate() throws HttpAuthenticationException {
            List<HttpServerAuthenticationMechanism> authenticationMechanisms = mechanismSupplier.get();
            try {
                boolean authenticationAttempted = false;
                for (HttpServerAuthenticationMechanism nextMechanism : authenticationMechanisms) {
                    currentMechanism = nextMechanism;
                    authenticationAttempted = authenticationAttempted | nextMechanism.evaluateRequest(this);

                    if (isAuthenticated()) {
                        return true;
                    }
                }
                currentMechanism = null;

                if (required || (authenticationAttempted && ignoreOptionalFailures == false)) {
                    responseCodeAllowed = true;
                    boolean challengeSent = false;
                    for (HttpServerAuthenticationMechanism nextMechanism : authenticationMechanisms) {
                        currentMechanism = nextMechanism;
                        challengeSent = challengeSent | nextMechanism.prepareResponse(this);
                    }
                    currentMechanism = null;

                    if (challengeSent == false && (required || (authenticationAttempted && ignoreOptionalFailures == false))) {
                        httpExchangeSpi.setResponseCode(FORBIDDEN);

                        return false;
                    } else if (challengeSent) {
                        httpExchangeSpi.setResponseCode(responseCode);
                        return false;
                    }
                }

                // If authentication was required it should have been picked up in the previous block.
                return true;
            } finally {
                authenticationMechanisms.forEach(m -> m.dispose());
            }
        }

        /**
         * @see org.wildfly.security.http.HttpServerExchange#setResponseCode(int)
         */
        @Override
        public void setResponseCode(int responseCode) {
            if (responseCodeAllowed == false) {
                throw log.responseCodeNotNow();
            }

            if (this.responseCode < 0 || responseCode != OK) {
                this.responseCode = responseCode;
            }
        }

        /**
         * @see org.wildfly.security.http.HttpServerExchange#authenticationComplete()
         */
        @Override
        public void authenticationComplete(SecurityIdentity securityIdentity) {
            authenticated = true;
            httpExchangeSpi.authenticationComplete(securityIdentity, currentMechanism.getMechanismName());
        }

        /**
         * @see org.wildfly.security.http.HttpServerExchange#authenticationFailed(java.lang.String)
         */
        @Override
        public void authenticationFailed(String message) {
            httpExchangeSpi.authenticationFailed(message, currentMechanism.getMechanismName());
        }

    }

    public static class Builder {

        private Supplier<List<HttpServerAuthenticationMechanism>> mechanismSupplier;
        private HttpExchangeSpi httpExchangeSpi;
        private boolean required;
        private boolean ignoreOptionalFailures;

        private Builder() {
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
         * @param required
         * @return
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
         * @param ignoreOptionalFailures
         * @return
         */
        public Builder setIgnoreOptionalFailures(final boolean ignoreOptionalFailures) {
            this.ignoreOptionalFailures = ignoreOptionalFailures;

            return this;
        }

        public HttpAuthenticator build() {
            return new HttpAuthenticator(mechanismSupplier, httpExchangeSpi, required, ignoreOptionalFailures);
        }

    }

}
