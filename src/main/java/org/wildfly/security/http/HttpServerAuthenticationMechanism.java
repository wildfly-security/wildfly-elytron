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

/**
 * Definition of a server side HTTP authentication mechanism.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public interface HttpServerAuthenticationMechanism {

    /**
     * Get the name of this mechanism, where appropriate this should be the IANA registered name.
     *
     * @return the name of the mechanism.
     */
    String getMechanismName();

    /**
     * Evaluate the current request and attempt to authenticate if appropriate.
     *
     * A successful or failed authentication should be indicated by calling {@link HttpServerExchange#authenticationComplete()}
     * or {@link HttpServerExchange#authenticationFailed(String)} respectively, if the mechanism throws an exception it will be
     * considered bad and not given an opportunity to send a challenge for the current exchange.
     *
     * @param exchange representation of the HTTP exchange.
     * @return {@code true} if this mechanism did attempt authentication on the incoming request regardless of the outcome of
     *         that attempt, {@code false} otherwise.
     * @throws HttpAuthenticationException If an problem occurs evaluating the request.
     */
    boolean evaluateRequest(HttpServerExchange exchange) throws HttpAuthenticationException;

    /**
     * Add an authentication challenge to the current response.
     *
     * Note: Some authentication mechanisms may not result in a challenge being sent.
     *
     * @param exchange representation of the HTTP exchange.
     * @return {@code true} if this mechanism adds to the response, {@code false} otherwise.
     * @throws HttpAuthenticationException if a problem occurs preparing the response.
     */
    boolean prepareResponse(HttpServerExchange exchange) throws HttpAuthenticationException;

    /**
     * Dispose of any resources currently held by this authentication mechanism.
     */
    default void dispose() {
    };

}
