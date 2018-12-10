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
import static org.wildfly.security._private.ElytronMessages.httpBasic;
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

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.wildfly.common.iteration.ByteIterator;
import org.wildfly.security.auth.callback.AvailableRealmsCallback;
import org.wildfly.security.http.HttpAuthenticationException;
import org.wildfly.security.http.HttpServerRequest;
import org.wildfly.security.http.HttpServerResponse;

/**
 * Implementation of the HTTP BASIC authentication mechanism
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
final class BasicAuthenticationMechanism extends UsernamePasswordAuthenticationMechanism {

    // TODO - Undertow also has a silent mode for HTTP authentication.

    private static final String CHALLENGE_PREFIX = "Basic ";
    private static final int PREFIX_LENGTH = CHALLENGE_PREFIX.length();

    private final boolean includeCharset;
    private final String configuredRealm;

    /**
     * Construct a new instance of {@code BasicAuthenticationMechanism}.
     *
     * @param callbackHandler the {@link CallbackHandler} to use to verify the supplied credentials and to notify to establish the current identity.
     * @param configuredRealm a configured realm name from the configuration.
     * @param includeCharset should the charset be included in the challenge.
     */
    BasicAuthenticationMechanism(final CallbackHandler callbackHandler, final String configuredRealm, final boolean includeCharset) {
        super(checkNotNullParam("callbackHandler", callbackHandler));

        this.includeCharset = includeCharset;
        this.configuredRealm = configuredRealm;
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
     * @see org.wildfly.security.http.HttpServerAuthenticationMechanism#evaluateRequest(HttpServerRequest)
     */
    @Override
    public void evaluateRequest(final HttpServerRequest request) throws HttpAuthenticationException {
        final String displayRealmName;
        String mechanismRealm = null;

        String[] realms = null;
        final AvailableRealmsCallback availableRealmsCallback = new AvailableRealmsCallback();
        try {
            callbackHandler.handle(new Callback[] { availableRealmsCallback });
            realms = availableRealmsCallback.getRealmNames();
        } catch (UnsupportedCallbackException ignored) {
        } catch (HttpAuthenticationException e) {
            throw e;
        } catch (IOException e) {
            throw httpBasic.mechCallbackHandlerFailedForUnknownReason(e).toHttpAuthenticationException();
        }

        if (configuredRealm != null) {
            displayRealmName = configuredRealm;
        } else if (realms != null && realms.length > 0) {
            displayRealmName = realms[0];
            mechanismRealm = displayRealmName;
        } else {
            displayRealmName = request.getFirstRequestHeaderValue(HOST);
        }

        if (mechanismRealm == null && realms != null && realms.length > 0) {
            for (String current : realms) {
                if (displayRealmName.equals(current)) {
                    mechanismRealm = displayRealmName;
                }
            }
            if (mechanismRealm == null) {
                mechanismRealm = realms[0];
            }
        }

        List<String> authorizationValues = request.getRequestHeaderValues(AUTHORIZATION);
        if (authorizationValues != null) {
            for (String current : authorizationValues) {
                if (current.startsWith(CHALLENGE_PREFIX)) {
                    byte[] decodedValue = ByteIterator.ofBytes(current.substring(PREFIX_LENGTH).getBytes(UTF_8)).asUtf8String().base64Decode().drain();

                    // Note: A ':' can not be present in the username but it can be present in the password so the first ':' is the delimiter.
                    int colonPos = indexOf(decodedValue, ':');
                    if (colonPos <= 0) {
                        // We flag as failed so the browser is re-challenged - sending an error the browser believes it's input was valid.
                        request.authenticationFailed(httpBasic.incorrectlyFormattedHeader(AUTHORIZATION), response -> prepareResponse(displayRealmName, response));
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

                        if (authenticate(mechanismRealm, username, password)) {
                            httpBasic.tracef("User %s authenticated successfully!", username);
                            if (authorize(username)) {
                                httpBasic.debugf("User %s authorization succeeded!", username);
                                succeed();

                                request.authenticationComplete();
                                return;
                            } else {
                                httpBasic.debugf("User %s authorization failed.", username);
                                fail();

                                request.authenticationFailed(httpBasic.authorizationFailed(username), response -> prepareResponse(displayRealmName, response));
                                return;
                            }

                        } else {
                            httpBasic.debugf("User %s authentication failed.", username);
                            fail();

                            request.authenticationFailed(httpBasic.authenticationFailed(username, BASIC_NAME), response -> prepareResponse(displayRealmName, response));
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

        request.noAuthenticationInProgress(response -> prepareResponse(displayRealmName, response));
    }

    private void prepareResponse(String realmName, HttpServerResponse response) {
        StringBuilder sb = new StringBuilder(CHALLENGE_PREFIX);
        sb.append(REALM).append("=\"").append(realmName).append("\"");
        if (includeCharset) {
            sb.append(", ").append(CHARSET).append("=\"UTF-8\"");
        }
        response.addResponseHeader(WWW_AUTHENTICATE, sb.toString());
        response.setStatusCode(UNAUTHORIZED);
    }

}
