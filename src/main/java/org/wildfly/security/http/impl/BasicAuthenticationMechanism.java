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
import javax.security.sasl.RealmCallback;

import org.wildfly.security.auth.callback.AuthenticationCompleteCallback;
import org.wildfly.security.auth.callback.EvidenceVerifyCallback;
import org.wildfly.security.auth.callback.SecurityIdentityCallback;
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
    private final String realm;

    BasicAuthenticationMechanism(final CallbackHandler callbackHandler, final String realm, final boolean includeCharset) {
        checkNotNullParam("callbackHandler", callbackHandler);

        this.callbackHandler = callbackHandler;
        this.includeCharset = includeCharset;
        this.realm = realm;
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

                            request.authenticationComplete(securityIdentityCallback.getSecurityIdentity());
                            return;
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
        RealmCallback realmCallback = realm != null ? new RealmCallback("User realm", realm) : null;
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

    private String getHostName(HttpServerRequest request) {
        return request.getFirstRequestHeaderValue(HOST);
    }

    private void prepareResponse(Supplier<String> hostnameSupplier, HttpServerResponse response) {
        String realmName = realm != null ? realm : hostnameSupplier.get();

        StringBuilder sb = new StringBuilder(CHALLENGE_PREFIX);
        sb.append(REALM).append("=\"").append(realmName).append("\"");
        if (includeCharset) {
            sb.append(", ").append(CHARSET).append("=\"UTF-8\"");
        }
        response.addResponseHeader(WWW_AUTHENTICATE, sb.toString());
        response.setResponseCode(UNAUTHORIZED);
    }

}
