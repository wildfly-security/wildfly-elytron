/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.sasl.oauth2;

import org.wildfly.common.Assert;
import org.wildfly.security.mechanism.AuthenticationMechanismException;
import org.wildfly.security.mechanism.oauth2.OAuth2Client;
import org.wildfly.security.mechanism.oauth2.OAuth2InitialClientMessage;
import org.wildfly.security.sasl.util.AbstractSaslClient;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslException;

import static org.wildfly.security.mechanism._private.ElytronMessages.saslOAuth2;

/**
 * An OAuth2 Sasl Client based on RFC-7628.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
final class OAuth2SaslClient extends AbstractSaslClient {

    private static final int S_FIRST_MESSAGE = 1;
    private static final int S_FINAL_SERVER_RESPONSE = 2;
    private final OAuth2Client oauth2Client;

    OAuth2SaslClient(final String mechanismName, final String protocol, final String serverName, final CallbackHandler callbackHandler, final String authorizationId, OAuth2Client oauth2Client) {
        super(mechanismName, protocol, serverName, callbackHandler, authorizationId, true, saslOAuth2);
        this.oauth2Client = oauth2Client;
        setNegotiationState(S_FIRST_MESSAGE);
    }

    public void dispose() throws SaslException {
        setNegotiationState(FAILED_STATE);
    }

    protected byte[] evaluateMessage(final int state, final byte[] challenge) throws SaslException {
        boolean ok = false;
        try {
            switch (state) {
                case S_FIRST_MESSAGE: {
                    if (challenge.length != 0) {
                        throw saslOAuth2.mechInitialChallengeMustBeEmpty().toSaslException();
                    }

                    OAuth2InitialClientMessage initialResponse = this.oauth2Client.getInitialResponse();

                    setNegotiationState(S_FINAL_SERVER_RESPONSE);
                    ok = true;

                    return initialResponse.getMessage();
                }
                case S_FINAL_SERVER_RESPONSE: {
                    byte[] finalMessage = this.oauth2Client.handleServerResponse(challenge);

                    // successful authentication
                    if (finalMessage == null) {
                        setNegotiationState(COMPLETE_STATE);
                        ok = true;
                    }

                    return finalMessage;
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
