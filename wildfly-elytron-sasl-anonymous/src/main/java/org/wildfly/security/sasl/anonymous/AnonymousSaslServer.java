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

import static org.wildfly.security.mechanism._private.ElytronMessages.saslAnonymous;

import java.nio.charset.StandardCharsets;

import org.wildfly.common.Assert;
import org.wildfly.security.auth.callback.AnonymousAuthorizationCallback;
import org.wildfly.security.sasl.util.AbstractSaslServer;
import org.wildfly.security.sasl.util.SaslMechanismInformation;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslException;

/**
 * A server implementation of the RFC 4505 {@code ANONYMOUS} mechanism.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class AnonymousSaslServer extends AbstractSaslServer {

    private static final int INITIAL_STATE = 1;

    /**
     * Construct a new instance.
     *
     * @param protocol the protocol
     * @param serverName the server name
     * @param callbackHandler the callback handler
     */
    AnonymousSaslServer(final String protocol, final String serverName, final CallbackHandler callbackHandler) {
        super(SaslMechanismInformation.Names.ANONYMOUS, protocol, serverName, callbackHandler, saslAnonymous);
        setNegotiationState(INITIAL_STATE);
    }

    /** {@inheritDoc} */
    public String getAuthorizationID() {
        return "anonymous";
    }

    @Override
    protected byte[] evaluateMessage(int state, final byte[] message) throws SaslException {
        switch (state) {
            case INITIAL_STATE:
                int length = message.length;
                if (length == 0) {
                    // need initial challenge
                    return NO_BYTES;
                } else {
                    // sanity check
                    if (length > 1020) {
                        throw saslAnonymous.mechAuthenticationNameTooLong().toSaslException();
                    }
                    String name = new String(message, StandardCharsets.UTF_8);
                    if (name.length() > 255) {
                        throw saslAnonymous.mechAuthenticationNameTooLong().toSaslException();
                    }
                    final AnonymousAuthorizationCallback callback = new AnonymousAuthorizationCallback(name);
                    handleCallbacks(callback);
                    if (! callback.isAuthorized()) {
                        throw saslAnonymous.mechAnonymousAuthorizationDenied().toSaslException();
                    }
                    negotiationComplete();
                    return null;
                }
        }
        throw Assert.impossibleSwitchCase(state);
    }
}
