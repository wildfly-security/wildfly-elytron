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
import org.wildfly.security.mechanism.oauth2.OAuth2InitialClientMessage;
import org.wildfly.security.mechanism.oauth2.OAuth2Server;
import org.wildfly.security.sasl.util.AbstractSaslServer;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslException;

import static org.wildfly.security.mechanism._private.ElytronMessages.saslOAuth2;

/**
 * An OAuth2 Sasl Server based on RFC-7628.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
final class OAuth2SaslServer extends AbstractSaslServer {

    private static final int S_FIRST_MESSAGE = 1;
    private static final int S_IN_ERROR = 2;
    private OAuth2Server oAuth2Server;

    OAuth2SaslServer(String mechanismName, String protocol, String serverName, CallbackHandler callbackHandler, OAuth2Server oAuth2Server) {
        super(mechanismName, protocol, serverName, callbackHandler, saslOAuth2);
        this.oAuth2Server = oAuth2Server;
        setNegotiationState(S_FIRST_MESSAGE);
    }

    @Override
    public String getAuthorizationID() {
        return null;
    }

    protected byte[] evaluateMessage(final int state, final byte[] response) throws SaslException {
        boolean ok = false;
        try {
            switch (state) {
                case S_FIRST_MESSAGE: {
                    if (response == null || response.length == 0) {
                        throw saslOAuth2.mechClientRefusesToInitiateAuthentication().toSaslException();
                    }

                    OAuth2InitialClientMessage initialClientMessage = this.oAuth2Server.parseInitialClientMessage(response);

                    byte[] serverResponse = this.oAuth2Server.evaluateInitialResponse(initialClientMessage);

                    // successful authentication, otherwise the server responds with an error message
                    if (serverResponse.length == 0) {
                        ok = true;
                        setNegotiationState(COMPLETE_STATE);
                    } else {
                        ok = true;
                        setNegotiationState(S_IN_ERROR);
                    }

                    return serverResponse;
                }
                case S_IN_ERROR: {
                    // client sent dummy client response, server fails the authentication
                    throw saslOAuth2.mechAuthenticationFailed().toSaslException();
                }
                case COMPLETE_STATE: {
                    if (response != null && response.length != 0) {
                        throw saslOAuth2.mechClientSentExtraMessage().toSaslException();
                    }
                    ok = true;
                    return null;
                }
                case FAILED_STATE: {
                    throw saslOAuth2.mechAuthenticationFailed().toSaslException();
                }
            }
            throw Assert.impossibleSwitchCase(state);
        } catch (AuthenticationMechanismException e) {
            throw e.toSaslException();
        } finally {
            if (!ok) {
                setNegotiationState(FAILED_STATE);
            }
        }
    }

    public void dispose() throws SaslException {
        setNegotiationState(FAILED_STATE);
    }
}

