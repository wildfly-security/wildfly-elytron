/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2014 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.sasl.util;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;

import org.wildfly.security.mechanism._private.ElytronMessages;

/**
 * A base class for SASL client implementations.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public abstract class AbstractSaslClient extends AbstractSaslParticipant implements SaslClient {

    private final String authorizationId;
    private final boolean hasInitialResponse;

    /**
     * Construct a new instance.
     *
     * @param mechanismName the SASL mechanism name
     * @param protocol the protocol
     * @param serverName the server name
     * @param callbackHandler the callback handler to use for authentication
     * @param authorizationId the possibly {@code null} protocol-dependent name used for authorization
     * @param hasInitialResponse {@code true} if the mechanism supports an initial response, {@code false} otherwise
     * @param log mechanism specific logger
     */
    protected AbstractSaslClient(final String mechanismName, final String protocol, final String serverName, final CallbackHandler callbackHandler, final String authorizationId, final boolean hasInitialResponse, ElytronMessages log) {
        super(mechanismName, protocol, serverName, callbackHandler, log);
        this.authorizationId = authorizationId;
        this.hasInitialResponse = hasInitialResponse;
    }


    /**
     * Construct a new instance.
     *
     * @param mechanismName the SASL mechanism name
     * @param protocol the protocol
     * @param serverName the server name
     * @param callbackHandler the callback handler to use for authentication
     * @param authorizationId the possibly {@code null} protocol-dependent name used for authorization
     * @param hasInitialResponse {@code true} if the mechanism supports an initial response, {@code false} otherwise
     * @param log mechanism specific logger
     */
    @Deprecated
    protected AbstractSaslClient(final String mechanismName, final String protocol, final String serverName, final CallbackHandler callbackHandler, final String authorizationId, final boolean hasInitialResponse, org.wildfly.security._private.ElytronMessages log) {
        super(mechanismName, protocol, serverName, callbackHandler, log);
        this.authorizationId = authorizationId;
        this.hasInitialResponse = hasInitialResponse;
    }

    /**
     * Construct a new instance.
     *
     * @param mechanismName the SASL mechanism name
     * @param protocol the protocol
     * @param serverName the server name
     * @param callbackHandler the callback handler to use for authentication
     * @param authorizationId the possibly {@code null} protocol-dependent name used for authorization
     * @param hasInitialResponse {@code true} if the mechanism supports an initial response, {@code false} otherwise
     */
    @Deprecated
    protected AbstractSaslClient(final String mechanismName, final String protocol, final String serverName, final CallbackHandler callbackHandler, final String authorizationId, final boolean hasInitialResponse) {
        super(mechanismName, protocol, serverName, callbackHandler);
        this.authorizationId = authorizationId;
        this.hasInitialResponse = hasInitialResponse;
    }

    /**
     * Evaluate an authentication challenge received from the server.
     *
     * @param challenge the authentication challenge
     * @return the response to send to the server
     * @throws SaslException if there is an error processing the server message
     */
    public byte[] evaluateChallenge(final byte[] challenge) throws SaslException {
        return evaluateMessage(challenge);
    }

    /**
     * Determines whether this mechanism has an optional initial response.
     * If true, caller should call {@link #evaluateChallenge(byte[])} with an
     * empty array to get the initial response.
     *
     * @return {@code true} if this mechanism has an initial response
     */
    public boolean hasInitialResponse() {
        return hasInitialResponse;
    }

    /**
     * Get the specified authorization ID.
     *
     * @return the authorization ID
     */
    protected String getAuthorizationId() {
        return authorizationId;
    }
}
