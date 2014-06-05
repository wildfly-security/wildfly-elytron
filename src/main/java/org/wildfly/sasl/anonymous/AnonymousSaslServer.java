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
