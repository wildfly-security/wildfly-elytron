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
package org.wildfly.security.http.impl;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.wildfly.security._private.ElytronMessages.log;
import static org.wildfly.security.http.HttpConstants.AUTHORIZATION;
import static org.wildfly.security.http.HttpConstants.NEGOTIATE;
import static org.wildfly.security.http.HttpConstants.SPNEGO_NAME;
import static org.wildfly.security.http.HttpConstants.UNAUTHORIZED;
import static org.wildfly.security.http.HttpConstants.WWW_AUTHENTICATE;

import java.io.IOException;
import java.util.List;
import java.util.Optional;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.AuthorizeCallback;

import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.wildfly.security.auth.callback.AuthenticationCompleteCallback;
import org.wildfly.security.auth.callback.ServerCredentialCallback;
import org.wildfly.security.credential.GSSCredentialCredential;
import org.wildfly.security.http.HttpAuthenticationException;
import org.wildfly.security.http.HttpScope;
import org.wildfly.security.http.HttpServerAuthenticationMechanism;
import org.wildfly.security.http.HttpServerRequest;
import org.wildfly.security.http.HttpServerResponse;
import org.wildfly.security.http.Scope;
import org.wildfly.security.mechanism.AuthenticationMechanismException;
import org.wildfly.security.mechanism.MechanismUtil;
import org.wildfly.security.util.ByteIterator;

/**
 * A {@link HttpServerAuthenticationMechanism} implementation to support SPNEGO.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class SpnegoAuthenticationMechanism implements HttpServerAuthenticationMechanism {

    private static final String CHALLENGE_PREFIX = NEGOTIATE + " ";

    private static final String GSS_CONTEXT_KEY = SpnegoAuthenticationMechanism.class.getName() + ".GSSContext";

    private final CallbackHandler callbackHandler;

    SpnegoAuthenticationMechanism(final CallbackHandler callbackHandler) {
        this.callbackHandler = callbackHandler;
    }

    @Override
    public String getMechanismName() {
        return SPNEGO_NAME;
    }

    @Override
    public void evaluateRequest(HttpServerRequest request) throws HttpAuthenticationException {
        HttpScope connectionScope = request.getScope(Scope.CONNECTION);
        GSSContext gssContext = connectionScope != null ? connectionScope.getAttachment(GSS_CONTEXT_KEY, GSSContext.class) : null;

        // Do we already have a cached identity? If so use it.
        if (gssContext != null && gssContext.isEstablished() && authorizeEstablishedContext(gssContext)) {
            request.authenticationComplete();
            return;
        }

        if (gssContext == null) {
            ServerCredentialCallback gssCredentialCallback = new ServerCredentialCallback(GSSCredentialCredential.class);
            final GSSCredential gssCredential;

            try {
                callbackHandler.handle(new Callback[] { gssCredentialCallback });
                GSSCredentialCredential credentialCredential = (GSSCredentialCredential) gssCredentialCallback.getCredential();
                gssCredential = credentialCredential != null ? credentialCredential.getGssCredential() : null;
            } catch (IOException | UnsupportedCallbackException e) {
                throw log.mechCallbackHandlerFailedForUnknownReason(SPNEGO_NAME, e).toHttpAuthenticationException();
            }

            if (gssCredential == null) {
                // We can't obtain a credential, we have no chance of performing SPNEGO authentication so give up now.
                request.noAuthenticationInProgress();
                return;
            }

            List<String> authorizationValues = request.getRequestHeaderValues(AUTHORIZATION);
            Optional<String> challenge = authorizationValues != null ? authorizationValues.stream()
                    .filter(s -> s.startsWith(CHALLENGE_PREFIX)).limit(1).map(s -> s.substring(CHALLENGE_PREFIX.length()))
                    .findFirst() : Optional.ofNullable(null);

            // Do we have an incoming response to a challenge? If so process it.
            if (challenge.isPresent()) {
                if (gssContext == null) {
                    GSSManager gssManager = GSSManager.getInstance();
                    try {
                        gssContext = gssManager.createContext(gssCredential);
                    } catch (GSSException e) {
                        throw log.mechUnableToCreateGssContext(SPNEGO_NAME, e).toHttpAuthenticationException();
                    }
                    if (connectionScope != null) {
                        connectionScope.setAttachment(GSS_CONTEXT_KEY, gssContext);
                    }
                }

                byte[] decodedValue = ByteIterator.ofBytes(challenge.get().getBytes(UTF_8)).base64Decode().drain();
                try {
                    final byte[] responseToken = gssContext.acceptSecContext(decodedValue, 0, decodedValue.length);

                    if (gssContext.isEstablished()) {
                        if (authorizeEstablishedContext(gssContext)) {
                            if (responseToken != null) {
                                request.authenticationComplete(
                                        response -> sendIntermediateChallenge(responseToken, response, true));
                            } else {
                                request.authenticationComplete();
                            }
                            return;
                        } else {
                            request.authenticationFailed(
                                    log.authorizationFailed(gssContext.getSrcName().toString(), SPNEGO_NAME));
                        }
                    } else if (responseToken != null) {
                        request.authenticationInProgress(response -> sendIntermediateChallenge(responseToken, response, false));
                        return;
                    }
                } catch (GSSException e) {
                    try {
                        MechanismUtil.handleCallbacks(SPNEGO_NAME, callbackHandler, AuthenticationCompleteCallback.FAILED);
                    } catch (AuthenticationMechanismException | UnsupportedCallbackException ignored) {
                    }
                    request.authenticationFailed(log.authenticationFailed(SPNEGO_NAME), this::sendBareChallenge);
                    return;
                }
            }
        }

        // No authentication yet so prepare to challenge.
        request.noAuthenticationInProgress(this::sendBareChallenge);
    }

    private void sendBareChallenge(HttpServerResponse response) {
        response.addResponseHeader(WWW_AUTHENTICATE, NEGOTIATE);
        response.setStatusCode(UNAUTHORIZED);
    }

    private void sendIntermediateChallenge(byte[] responseToken, HttpServerResponse response, boolean complete) {
        String responseConverted = ByteIterator.ofBytes(responseToken).base64Encode().drainToString();
        response.addResponseHeader(WWW_AUTHENTICATE, CHALLENGE_PREFIX + responseConverted);
        if (complete == false) {
            response.setStatusCode(UNAUTHORIZED);
        }
    }

    private boolean authorizeEstablishedContext(GSSContext gssContext) throws HttpAuthenticationException {
        assert gssContext.isEstablished();

        boolean authorized = false;
        try {
            String clientName = gssContext.getSrcName().toString();
            AuthorizeCallback authorize = new AuthorizeCallback(clientName, clientName);
            callbackHandler.handle(new Callback[] {authorize});

            authorized = authorize.isAuthorized();
        } catch (GSSException e) {
            try {
                MechanismUtil.handleCallbacks(SPNEGO_NAME, callbackHandler, AuthenticationCompleteCallback.FAILED);
            } catch (AuthenticationMechanismException | UnsupportedCallbackException ignored) {
            }
            throw log.mechServerSideAuthenticationFailed(SPNEGO_NAME, e).toHttpAuthenticationException();
        } catch (IOException e) {
            throw log.mechServerSideAuthenticationFailed(SPNEGO_NAME, e).toHttpAuthenticationException();
        } catch (UnsupportedCallbackException ignored) {
        }

        try {
            MechanismUtil.handleCallbacks(SPNEGO_NAME, callbackHandler, authorized ? AuthenticationCompleteCallback.SUCCEEDED : AuthenticationCompleteCallback.FAILED);
        } catch (AuthenticationMechanismException e) {
            throw e.toHttpAuthenticationException();
        } catch (UnsupportedCallbackException ignored) {
        }

        return authorized;
    }

}
