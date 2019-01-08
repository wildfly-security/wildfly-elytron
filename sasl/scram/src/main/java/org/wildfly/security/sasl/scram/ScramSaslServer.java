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

package org.wildfly.security.sasl.scram;

import static org.wildfly.security.mechanism._private.ElytronMessages.saslScram;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslException;

import org.wildfly.common.Assert;
import org.wildfly.security.auth.callback.ChannelBindingCallback;
import org.wildfly.security.mechanism.AuthenticationMechanismException;
import org.wildfly.security.mechanism.ScramServerException;
import org.wildfly.security.mechanism.scram.ScramFinalClientMessage;
import org.wildfly.security.mechanism.scram.ScramFinalServerMessage;
import org.wildfly.security.mechanism.scram.ScramInitialClientMessage;
import org.wildfly.security.mechanism.scram.ScramInitialServerResult;
import org.wildfly.security.mechanism.scram.ScramServer;
import org.wildfly.security.sasl.util.AbstractSaslServer;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 * @author <a href="mailto:jkalina@redhat.com">Jan Kalina</a>
 */
final class ScramSaslServer extends AbstractSaslServer {

    private static final int S_NO_MESSAGE = 1;
    private static final int S_FIRST_MESSAGE = 2;
    private static final int S_FINAL_MESSAGE = 3;

    private final ScramServer scramServer;
    private final ChannelBindingCallback bindingCallback;

    private String authorizationId;

    private ScramInitialServerResult initialServerResult;
    private ScramInitialClientMessage initialClientMessage;

    ScramSaslServer(final String mechanismName, final String protocol, final String serverName, final CallbackHandler callbackHandler, final ScramServer scramServer, final ChannelBindingCallback bindingCallback) {
        super(mechanismName, protocol, serverName, callbackHandler, saslScram);
        this.scramServer = scramServer;
        this.bindingCallback = bindingCallback;
        setNegotiationState(S_NO_MESSAGE);
    }

    public String getAuthorizationID() {
        return authorizationId;
    }

    protected byte[] evaluateMessage(final int state, final byte[] response) throws SaslException {
        boolean ok = false;
        try {
            switch (state) {
                case S_NO_MESSAGE: {
                    if (response == null || response.length == 0) {
                        setNegotiationState(S_FIRST_MESSAGE);
                        // initial challenge
                        ok = true;
                        return NO_BYTES;
                    }
                    // fall through
                }
                case S_FIRST_MESSAGE: {
                    if (response == null || response.length == 0) {
                        throw saslScram.mechClientRefusesToInitiateAuthentication().toSaslException();
                    }
                    final ScramInitialClientMessage initialClientMessage = scramServer.parseInitialClientMessage(bindingCallback, response);
                    final ScramInitialServerResult initialServerResult = scramServer.evaluateInitialResponse(initialClientMessage);
                    this.initialClientMessage = initialClientMessage;
                    this.initialServerResult = initialServerResult;
                    final String authorizationId = initialClientMessage.getAuthorizationId();
                    this.authorizationId = authorizationId == null ? initialClientMessage.getAuthenticationName() : authorizationId;
                    setNegotiationState(S_FINAL_MESSAGE);
                    ok = true;
                    return initialServerResult.getScramInitialChallenge().getMessageBytes();
                }
                case S_FINAL_MESSAGE: {
                    final ScramFinalClientMessage finalClientMessage = scramServer.parseFinalClientMessage(initialClientMessage, initialServerResult, response);
                    final ScramFinalServerMessage finalServerMessage = scramServer.evaluateFinalClientMessage(initialServerResult, finalClientMessage);
                    setNegotiationState(COMPLETE_STATE);
                    ok = true;
                    return finalServerMessage.getMessageBytes();
                }
                case COMPLETE_STATE: {
                    if (response != null && response.length != 0) {
                        throw saslScram.mechClientSentExtraMessage().toSaslException();
                    }
                    ok = true;
                    return null;
                }
                case FAILED_STATE: {
                    throw saslScram.mechAuthenticationFailed().toSaslException();
                }
            }
            throw Assert.impossibleSwitchCase(state);
        } catch (ScramServerException cause) {
            ok = false;
            setNegotiationState(FAILED_STATE);
            if (saslScram.isDebugEnabled()) {
                saslScram.debugf(cause, "[%s] error when evaluating message from client during state [%s]: %s", getMechanismName(), state, cause.getError().getText());
            }
            return cause.getError().getMessageBytes();
        } catch (AuthenticationMechanismException e) {
            throw e.toSaslException();
        } finally {
            if (! ok) {
                setNegotiationState(FAILED_STATE);
            }
        }
    }

    public void dispose() throws SaslException {
        initialServerResult = null;
        initialClientMessage = null;
        setNegotiationState(FAILED_STATE);
    }
}
