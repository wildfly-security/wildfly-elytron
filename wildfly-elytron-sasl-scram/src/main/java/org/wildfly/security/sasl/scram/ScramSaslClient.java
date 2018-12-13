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
import org.wildfly.security.mechanism.AuthenticationMechanismException;
import org.wildfly.security.mechanism.scram.ScramClient;
import org.wildfly.security.mechanism.scram.ScramFinalClientMessage;
import org.wildfly.security.mechanism.scram.ScramFinalServerMessage;
import org.wildfly.security.mechanism.scram.ScramInitialClientMessage;
import org.wildfly.security.mechanism.scram.ScramInitialServerMessage;
import org.wildfly.security.sasl.util.AbstractSaslClient;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
final class ScramSaslClient extends AbstractSaslClient {

    private static final int ST_NEW = 1;
    private static final int ST_R1_SENT = 2;
    private static final int ST_R2_SENT = 3;

    private final ScramClient scramClient;

    private ScramInitialClientMessage initialResponse;
    private ScramFinalClientMessage finalResponse;

    ScramSaslClient(final String mechanismName, final String protocol, final String serverName, final CallbackHandler callbackHandler, final String authorizationId, final ScramClient scramClient) {
        super(mechanismName, protocol, serverName, callbackHandler, authorizationId, true, saslScram);
        this.scramClient = scramClient;
        setNegotiationState(ST_NEW);
    }

    public void dispose() throws SaslException {
        initialResponse = null;
        finalResponse = null;
        setNegotiationState(FAILED_STATE);
    }

    protected byte[] evaluateMessage(final int state, final byte[] challenge) throws SaslException {
        boolean ok = false;
        try {
            switch (state) {
                case ST_NEW: {
                    // initial response
                    if (challenge.length != 0) throw saslScram.mechInitialChallengeMustBeEmpty().toSaslException();
                    this.initialResponse = scramClient.getInitialResponse();
                    setNegotiationState(ST_R1_SENT);
                    ok = true;
                    return initialResponse.getMessageBytes();
                }
                case ST_R1_SENT: {
                    final ScramInitialServerMessage initialChallenge = scramClient.parseInitialServerMessage(initialResponse, challenge);
                    this.finalResponse = scramClient.handleInitialChallenge(initialResponse, initialChallenge);
                    setNegotiationState(ST_R2_SENT);
                    ok = true;
                    return finalResponse.getMessageBytes();
                }
                case ST_R2_SENT: {
                    final ScramFinalServerMessage finalChallenge = scramClient.parseFinalServerMessage(challenge);
                    scramClient.verifyFinalChallenge(finalResponse, finalChallenge);
                    setNegotiationState(COMPLETE_STATE);
                    ok = true;
                    return null;
                }
            }
            throw Assert.impossibleSwitchCase(state);
        } catch (AuthenticationMechanismException e) {
            throw e.toSaslException();
        } finally {
            if (! ok) {
                setNegotiationState(FAILED_STATE);
            }
        }
    }
}
