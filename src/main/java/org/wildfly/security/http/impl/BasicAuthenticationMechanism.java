/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2015 Red Hat, Inc., and individual contributors
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
import static java.util.Arrays.fill;
import static org.wildfly.common.Assert.checkNotNullParam;
import static org.wildfly.security._private.ElytronMessages.log;
import static org.wildfly.security.http.HttpConstants.AUTHORIZATION;
import static org.wildfly.security.http.HttpConstants.BASIC_NAME;
import static org.wildfly.security.http.HttpConstants.CHARSET;
import static org.wildfly.security.http.HttpConstants.HOST;
import static org.wildfly.security.http.HttpConstants.REALM;
import static org.wildfly.security.http.HttpConstants.UNAUTHORIZED;
import static org.wildfly.security.http.HttpConstants.WWW_AUTHENTICATE;
import static org.wildfly.security.util._private.Arrays2.indexOf;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.util.List;
import java.util.function.Supplier;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.AuthorizeCallback;
import javax.security.sasl.RealmCallback;

import org.wildfly.security.auth.callback.AuthenticationCompleteCallback;
import org.wildfly.security.auth.callback.EvidenceVerifyCallback;
import org.wildfly.security.evidence.PasswordGuessEvidence;
import org.wildfly.security.http.HttpAuthenticationException;
import org.wildfly.security.http.HttpServerAuthenticationMechanism;
import org.wildfly.security.http.HttpServerRequest;
import org.wildfly.security.http.HttpServerResponse;
import org.wildfly.security.util.ByteIterator;

/**
 * Implementation of the HTTP BASIC authentication mechanism
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class BasicAuthenticationMechanism implements HttpServerAuthenticationMechanism {

    // TODO - Undertow also has a silent mode for HTTP authentication.

    private static final String CHALLENGE_PREFIX = "Basic ";
    private static final int PREFIX_LENGTH = CHALLENGE_PREFIX.length();

    private final CallbackHandler callbackHandler;
    private final boolean includeCharset;
    private final String mechanismRealm;
    private final String displayRealm;

    /**
     * Construct a new instance of {@code BasicAuthenticationMechanism}.
     *
     * @param callbackHandler the {@link CallbackHandler} to use to verify the supplied credentials and to notify to establish the current identity.
     * @param mechanismRealm the name of the realm to be passed back in the callbacks for authentication.
     * @param displayRealm the realm name that should be sent in the challenge to the client, if {@code null} the name of the host will be sent instead.
     * @param includeCharset should the charset be included in the challenge.
     */
    BasicAuthenticationMechanism(final CallbackHandler callbackHandler, final String mechanismRealm, final String displayRealm, final boolean includeCharset) {
        checkNotNullParam("callbackHandler", callbackHandler);

        this.callbackHandler = callbackHandler;
        this.includeCharset = includeCharset;
        this.mechanismRealm = mechanismRealm;
        this.displayRealm = displayRealm;
    }

    /**
     * @see org.wildfly.security.http.HttpServerAuthenticationMechanism#getMechanismName()
     */
    @Override
    public String getMechanismName() {
        return BASIC_NAME;
    }

    /**
     * @throws HttpAuthenticationException
     * @see org.wildfly.security.http.HttpServerAuthenticationMechanism#evaluateRequest(org.wildfly.security.http.HttpRequest)
     */
    @Override
    public void evaluateRequest(final HttpServerRequest request) throws HttpAuthenticationException {
        List<String> authorizationValues = request.getRequestHeaderValues(AUTHORIZATION);
        if (authorizationValues != null) {
            for (String current : authorizationValues) {
                if (current.startsWith(CHALLENGE_PREFIX)) {
                    byte[] decodedValue = ByteIterator.ofBytes(current.substring(PREFIX_LENGTH).getBytes(UTF_8)).base64Decode().drain();

                    // Note: A ':' can not be present in the username but it can be present in the password so the first ':' is the delimiter.
                    int colonPos = indexOf(decodedValue, ':');
                    if (colonPos <= 0) {
                        // We flag as failed so the browser is re-challenged - sending an error the browser believes it's input was valid.
                        request.authenticationFailed(log.incorrectlyFormattedHeader(AUTHORIZATION), response -> prepareResponse(() -> getHostName(request), response));
                        return;
                    }

                    ByteBuffer usernameBytes = ByteBuffer.wrap(decodedValue, 0, colonPos);
                    ByteBuffer passwordBytes = ByteBuffer.wrap(decodedValue, colonPos + 1, decodedValue.length - colonPos - 1);

                    CharBuffer usernameChars = UTF_8.decode(usernameBytes);
                    CharBuffer passwordChars = UTF_8.decode(passwordBytes);

                    char[] password = new char[passwordChars.length()];
                    passwordChars.get(password);
                    try {
                        String username = usernameChars.toString();
                        if (authenticate(username, passwordChars.array())) {
                            if (authorize(username)) {
                                callbackHandler.handle(new Callback[] { AuthenticationCompleteCallback.SUCCEEDED });

                                request.authenticationComplete();
                                return;
                            } else {
                                callbackHandler.handle(new Callback[] { AuthenticationCompleteCallback.FAILED });
                                request.authenticationFailed(log.authorizationFailed(username, BASIC_NAME), response -> prepareResponse(() -> getHostName(request), response));
                                return;
                            }

                        } else {
                            callbackHandler.handle(new Callback[] { AuthenticationCompleteCallback.FAILED });
                            request.authenticationFailed(log.authenticationFailed(username, BASIC_NAME), response -> prepareResponse(() -> getHostName(request), response));
                            return;
                        }
                    } catch (IOException | UnsupportedCallbackException e) {
                        throw new HttpAuthenticationException(e);
                    } finally {
                        fill(password, (char) 0x00);
                        if (passwordChars.hasArray()) {
                            fill(passwordChars.array(), (char) 0x00);
                        }
                    }
                }
            }
        }

        request.noAuthenticationInProgress(response -> prepareResponse(() -> getHostName(request), response));
    }

    private boolean authenticate(String username, char[] password) throws HttpAuthenticationException {
        RealmCallback realmCallback = mechanismRealm != null ? new RealmCallback("User realm", mechanismRealm) : null;
        NameCallback nameCallback = new NameCallback("Remote Authentication Name", username);
        nameCallback.setName(username);
        final PasswordGuessEvidence evidence = new PasswordGuessEvidence(password);
        EvidenceVerifyCallback evidenceVerifyCallback = new EvidenceVerifyCallback(evidence);

        try {
            final Callback[] callbacks;
            if (realmCallback != null) {
                callbacks = new Callback[] { realmCallback, nameCallback, evidenceVerifyCallback };
            } else {
                callbacks = new Callback[] { nameCallback, evidenceVerifyCallback };
            }

            callbackHandler.handle(callbacks);

            return evidenceVerifyCallback.isVerified();
        } catch (UnsupportedCallbackException e) {
            return false;
        } catch (IOException e) {
            throw new HttpAuthenticationException(e);
        } finally {
            evidence.destroy();
        }
    }

    private boolean authorize(String username) throws HttpAuthenticationException {
        AuthorizeCallback authorizeCallback = new AuthorizeCallback(username, username);

        try {
            callbackHandler.handle(new Callback[] {authorizeCallback});

            return authorizeCallback.isAuthorized();
        } catch (UnsupportedCallbackException e) {
            return false;
        } catch (IOException e) {
            throw new HttpAuthenticationException(e);
        }
    }

    private String getHostName(HttpServerRequest request) {
        return request.getFirstRequestHeaderValue(HOST);
    }

    private void prepareResponse(Supplier<String> hostnameSupplier, HttpServerResponse response) {
        String realmName = displayRealm != null ? displayRealm : hostnameSupplier.get();

        StringBuilder sb = new StringBuilder(CHALLENGE_PREFIX);
        sb.append(REALM).append("=\"").append(realmName).append("\"");
        if (includeCharset) {
            sb.append(", ").append(CHARSET).append("=\"UTF-8\"");
        }
        response.addResponseHeader(WWW_AUTHENTICATE, sb.toString());
        response.setStatusCode(UNAUTHORIZED);
    }

}
