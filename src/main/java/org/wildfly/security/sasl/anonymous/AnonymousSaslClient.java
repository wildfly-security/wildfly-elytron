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

package org.wildfly.security.sasl.anonymous;

import static org.wildfly.security.sasl.anonymous.AbstractAnonymousFactory.ANONYMOUS;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.sasl.SaslException;

import org.wildfly.security.sasl.util.AbstractSaslClient;
import org.wildfly.security.sasl.util.StringPrep;
import org.wildfly.security.util.ByteStringBuilder;

/**
 * A client implementation of the RFC 4505 {@code ANONYMOUS} mechanism.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class AnonymousSaslClient extends AbstractSaslClient {

    private static final int INITIAL_STATE = 1;

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
        setNegotiationState(INITIAL_STATE);
    }

    @Override
    protected byte[] evaluateMessage(int state, final byte[] message) throws SaslException {
        switch (state) {
            case INITIAL_STATE:
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
                negotiationComplete();
                return b.toArray();
        }
        throw new SaslException("Invalid state");
    }
}
