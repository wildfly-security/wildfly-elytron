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
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;

import org.wildfly.security.mechanism._private.ElytronMessages;

/**
 * A base class for SASL client implementations.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public abstract class AbstractSaslServer extends AbstractSaslParticipant implements SaslServer {

    /**
     * Construct a new instance.
     *
     * @param mechanismName the name of the defined mechanism
     * @param protocol the protocol
     * @param serverName the server name
     * @param callbackHandler the callback handler
     * @param log mechanism specific logger
     */
    protected AbstractSaslServer(final String mechanismName, final String protocol, final String serverName, final CallbackHandler callbackHandler, ElytronMessages log) {
        super(mechanismName, protocol, serverName, callbackHandler, log);
    }

    /**
     * Construct a new instance.
     *
     * @param mechanismName the name of the defined mechanism
     * @param protocol the protocol
     * @param serverName the server name
     * @param callbackHandler the callback handler
     * @param log mechanism specific logger
     */
    @Deprecated
    protected AbstractSaslServer(final String mechanismName, final String protocol, final String serverName, final CallbackHandler callbackHandler, org.wildfly.security._private.ElytronMessages log) {
        super(mechanismName, protocol, serverName, callbackHandler, log);
    }

    /**
     * Construct a new instance.
     *
     * @param mechanismName the name of the defined mechanism
     * @param protocol the protocol
     * @param serverName the server name
     * @param callbackHandler the callback handler
     */
    @Deprecated
    protected AbstractSaslServer(final String mechanismName, final String protocol, final String serverName, final CallbackHandler callbackHandler) {
        super(mechanismName, protocol, serverName, callbackHandler);
    }

    /**
     * Evaluate an authentication response received from the client.
     *
     * @param response the authentication response
     * @return the next challenge to send to the client
     * @throws SaslException if there is an error processing the client message
     */
    public byte[] evaluateResponse(final byte[] response) throws SaslException {
        return evaluateMessage(response);
    }
}
