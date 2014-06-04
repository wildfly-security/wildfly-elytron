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
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;

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
     */
    protected AbstractSaslServer(final String mechanismName, final String protocol, final String serverName, final CallbackHandler callbackHandler) {
        super(mechanismName, protocol, serverName, callbackHandler);
    }

    /**
     * Evaluate an authentication response received from the client.
     *
     * @param response the authentication response
     * @return the response to send to the server
     * @throws SaslException if there is an error processing the server message
     */
    public byte[] evaluateResponse(final byte[] response) throws SaslException {
        return evaluateMessage(response);
    }
}
