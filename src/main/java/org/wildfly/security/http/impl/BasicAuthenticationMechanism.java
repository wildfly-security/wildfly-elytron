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
import static org.wildfly.security.http.HttpConstants.BASIC;
import static org.wildfly.security.http.HttpConstants.CHARSET;
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
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.wildfly.security.auth.callback.AuthenticationCompleteCallback;
import org.wildfly.security.auth.callback.PasswordVerifyCallback;
import org.wildfly.security.auth.callback.SecurityIdentityCallback;
import org.wildfly.security.http.HttpAuthenticationException;
import org.wildfly.security.http.HttpServerAuthenticationMechanism;
import org.wildfly.security.http.HttpServerExchange;
import org.wildfly.security.util.ByteIterator;

/**
 * Implementation of the HTTP BASIC authentication mechanism
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class BasicAuthenticationMechanism implements HttpServerAuthenticationMechanism {

    // TODO - Undertow also has a silent mode for HTTP authentication.

    private static final String BASIC_PREFIX = BASIC + " ";
    private static final int PREFIX_LENGTH = BASIC_PREFIX.length();

    private final CallbackHandler callbackHandler;
    private final String challengeValue;

    BasicAuthenticationMechanism(final CallbackHandler callbackHandler, final String realm, final boolean includeCharset) {
        checkNotNullParam("callbackHandler", callbackHandler);
        checkNotNullParam("realm", realm);

        this.callbackHandler = callbackHandler;

        StringBuilder sb = new StringBuilder(BASIC_PREFIX);
        sb.append(REALM).append("=\"").append(realm).append("\"");
        if (includeCharset) {
            sb.append(", ").append(CHARSET).append("=\"UTF-8\"");
        }
        challengeValue = sb.toString();

    }

    /**
     * @see org.wildfly.security.http.HttpServerAuthenticationMechanism#getMechanismName()
     */
    @Override
    public String getMechanismName() {
        return BASIC;
    }

    /**
     * @throws HttpAuthenticationException
     * @see org.wildfly.security.http.HttpServerAuthenticationMechanism#evaluateRequest(org.wildfly.security.http.HttpRequest)
     */
    @Override
    public boolean evaluateRequest(HttpServerExchange exchange) throws HttpAuthenticationException {
        List<String> authorizationValues = exchange.getRequestHeaderValues(AUTHORIZATION);
        if (authorizationValues != null) {
            for (String current : authorizationValues) {
                if (current.startsWith(BASIC_PREFIX)) {
                    byte[] decodedValue = ByteIterator.ofBytes(current.substring(PREFIX_LENGTH).getBytes(UTF_8)).base64Decode().drain();

                    int colonPos = indexOf(decodedValue, ':');
                    if (colonPos <= 0 || colonPos == decodedValue.length-1) {
                        throw log.incorrectlyFormattedHeader(AUTHORIZATION);
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
                            SecurityIdentityCallback securityIdentityCallback = new SecurityIdentityCallback();
                            callbackHandler.handle(new Callback[] { AuthenticationCompleteCallback.SUCCEEDED, securityIdentityCallback });

                            exchange.authenticationComplete(securityIdentityCallback.getSecurityIdentity());
                        } else {
                            callbackHandler.handle(new Callback[] { AuthenticationCompleteCallback.FAILED });
                            exchange.authenticationFailed(log.authenticationFailed(username, BASIC));
                        }
                    } catch (IOException | UnsupportedCallbackException e) {
                        throw new HttpAuthenticationException(e);
                    } finally {
                        fill(password, (char) 0x00);
                        if (passwordChars.hasArray()) {
                            fill(passwordChars.array(), (char) 0x00);
                        }
                    }

                    return true;
                }
            }
        }

        return false;
    }

    private boolean authenticate(String username, char[] password) throws HttpAuthenticationException {
        NameCallback nameCallback = new NameCallback("Remote Authentication Name", username);
        nameCallback.setName(username);
        PasswordVerifyCallback passwordVerifyCallback = new PasswordVerifyCallback(password);

        try {
            callbackHandler.handle(new Callback[] { nameCallback, passwordVerifyCallback });

            return passwordVerifyCallback.isVerified();
        } catch (IOException | UnsupportedCallbackException e) {
            throw new HttpAuthenticationException(e);
        } finally {
            passwordVerifyCallback.clearPassword();
        }
    }

    /**
     * @see org.wildfly.security.http.HttpServerAuthenticationMechanism#prepareResponse(org.wildfly.security.http.HttpResponse)
     */
    @Override
    public boolean prepareResponse(HttpServerExchange exchange) {

        exchange.addResponseHeader(WWW_AUTHENTICATE, challengeValue);
        exchange.setResponseCode(UNAUTHORIZED);

        return true;
    }

}
