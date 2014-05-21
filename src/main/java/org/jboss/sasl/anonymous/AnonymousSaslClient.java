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

package org.jboss.sasl.anonymous;

import static org.jboss.sasl.anonymous.AbstractAnonymousFactory.ANONYMOUS;

import org.jboss.sasl.util.AbstractSaslClient;
import org.jboss.sasl.util.ByteStringBuilder;
import org.jboss.sasl.util.SaslState;
import org.jboss.sasl.util.SaslStateContext;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.sasl.SaslException;
import org.jboss.sasl.util.StringPrep;

/**
 * A client implementation of the RFC 4505 {@code ANONYMOUS} mechanism.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class AnonymousSaslClient extends AbstractSaslClient {

    private final SaslState initial = new SaslState() {
        public byte[] evaluateMessage(final SaslStateContext context, final byte[] message) throws SaslException {
            if (message != null && message.length > 0) {
                throw new SaslException("Invalid challenge received from server");
            }
            NameCallback nameCallback = new NameCallback("Authentication name");
            handleCallbacks(nameCallback);
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
            ByteStringBuilder b = new ByteStringBuilder();
            StringPrep.encode(name, b, 0
                | StringPrep.MAP_TO_NOTHING
                | StringPrep.MAP_TO_SPACE
                | StringPrep.FORBID_ASCII_CONTROL
                | StringPrep.FORBID_NON_ASCII_CONTROL
                | StringPrep.FORBID_PRIVATE_USE
                | StringPrep.FORBID_NON_CHARACTER
                | StringPrep.FORBID_SURROGATE
                | StringPrep.FORBID_INAPPROPRIATE_FOR_PLAIN_TEXT
                | StringPrep.FORBID_CHANGE_DISPLAY_AND_DEPRECATED
                | StringPrep.FORBID_TAGGING
                | StringPrep.NORMALIZE_KC
            );
            context.negotiationComplete();
            return b.toArray();
        }
    };

    /**
     * Construct a new instance.
     *
     * @param protocol the protocol
     * @param serverName the server name
     * @param callbackHandler the callback handler to use for authentication
     * @param authorizationId the possibly {@code null} protocol-dependent name used for authorization
     */
    protected AnonymousSaslClient(final String protocol, final String serverName, final CallbackHandler callbackHandler, final String authorizationId) {
        super(ANONYMOUS, protocol, serverName, callbackHandler, authorizationId, true);
        getContext().setNegotiationState(initial);
    }
}
