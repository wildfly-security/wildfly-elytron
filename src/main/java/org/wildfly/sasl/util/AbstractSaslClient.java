/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2011, Red Hat, Inc., and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */

package org.wildfly.sasl.util;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;

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
     */
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
