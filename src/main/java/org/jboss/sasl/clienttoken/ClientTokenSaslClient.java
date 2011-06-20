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

package org.jboss.sasl.clienttoken;

import org.jboss.sasl.callback.TokenCallback;
import org.jboss.sasl.util.AbstractSaslClient;
import org.jboss.sasl.util.Charsets;
import org.jboss.sasl.util.SaslState;
import org.jboss.sasl.util.SaslStateContext;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.sasl.SaslException;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class ClientTokenSaslClient extends AbstractSaslClient {

    private final SaslState initial = new SaslState() {
        public byte[] evaluateMessage(final SaslStateContext context, final byte[] message) throws SaslException {
            if (message != null && message.length > 0) {
                throw new SaslException("Invalid challenge received from server");
            }
            NameCallback nameCallback = new NameCallback("Authentication name");
            TokenCallback tokenCallback = new TokenCallback("Authentication token", 16);
            handleCallbacks(nameCallback, tokenCallback);
            String name = nameCallback.getName();
            if (name == null) {
                throw new SaslException("Authentication name is missing");
            }
            if (name.length() > 255) {
                throw new SaslException("Authentication name string is too long");
            }
            if (name.isEmpty()) {
                throw new SaslException("Authentication name is empty");
            }
            final byte[] token = tokenCallback.getToken();
            if (token.length != 16) {
                throw new SaslException("Authentication token is not the correct length");
            }
            final byte[] bytes = name.getBytes(Charsets.UTF_8);
            final byte[] out = new byte[1 + token.length + 1 + bytes.length];
            out[0] = 16;
            System.arraycopy(token, 0, out, 1, 16);
            out[17] = (byte) bytes.length;
            System.arraycopy(bytes, 0, out, 18, bytes.length);
            context.negotiationComplete();
            return out;
        }
    };

    /**
     * Construct a new instance.
     *
     * @param protocol the protocol
     * @param serverName the server name
     * @param callbackHandler the callback handler
     * @param authorizationId the authorization ID
     */
    public ClientTokenSaslClient(final String protocol, final String serverName, final CallbackHandler callbackHandler, final String authorizationId) {
        super("CLIENT-TOKEN", protocol, serverName, callbackHandler, authorizationId, true);
        getContext().setNegotiationState(initial);
    }
}
