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

package org.wildfly.sasl.anonymous;

import static org.wildfly.sasl.anonymous.AbstractAnonymousFactory.ANONYMOUS;

import org.wildfly.sasl.util.AbstractSaslServer;
import org.wildfly.sasl.util.Charsets;
import org.wildfly.sasl.util.SaslState;
import org.wildfly.sasl.util.SaslStateContext;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslException;

/**
 * A server implementation of the RFC 4505 {@code ANONYMOUS} mechanism.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class AnonymousSaslServer extends AbstractSaslServer {

    private static final SaslState INITIAL = new SaslState() {
        public byte[] evaluateMessage(final SaslStateContext context, final byte[] message) throws SaslException {
            int length = message.length;
            if (length == 0) {
                // need initial challenge
                return NO_BYTES;
            } else {
                // sanity check
                if (length > 1020) {
                    throw new SaslException("Authentication name string is too long");
                }
                String name = new String(message, Charsets.UTF_8);
                if (name.length() > 255) {
                    throw new SaslException("Authentication name string is too long");
                }
                context.negotiationComplete();
                return null;
            }
        }
    };

    /**
     * Construct a new instance.
     *
     * @param protocol the protocol
     * @param serverName the server name
     * @param callbackHandler the callback handler
     */
    public AnonymousSaslServer(final String protocol, final String serverName, final CallbackHandler callbackHandler) {
        super(ANONYMOUS, protocol, serverName, callbackHandler);
        getContext().setNegotiationState(INITIAL);
    }

    /** {@inheritDoc} */
    public String getAuthorizationID() {
        return "anonymous";
    }
}
