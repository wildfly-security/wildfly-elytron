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
     * The mechanism should call the appropriate callback methods on the {link HttpServerResponse} to both indicate the outcome
     * of the evaluation and to register any {@link HttpServerMechanismsResponder} as required.
     *
     * @param request representation of the HTTP request.
     * @throws HttpAuthenticationException if there is an internal failure handling the authentication.
     */
    void evaluateRequest(HttpServerRequest request) throws HttpAuthenticationException;

    /**
     * Dispose of any resources currently held by this authentication mechanism.
     */
    default void dispose() {
    };

}
