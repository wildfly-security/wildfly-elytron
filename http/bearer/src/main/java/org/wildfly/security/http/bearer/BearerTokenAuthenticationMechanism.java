/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2017 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.wildfly.security.http.bearer;

import static org.wildfly.security.http.HttpConstants.BEARER_TOKEN;
import static org.wildfly.security.http.HttpConstants.FORBIDDEN;
import static org.wildfly.security.http.HttpConstants.REALM;
import static org.wildfly.security.http.HttpConstants.UNAUTHORIZED;
import static org.wildfly.security.http.HttpConstants.WWW_AUTHENTICATE;
import static org.wildfly.security.mechanism._private.ElytronMessages.httpBearer;

import java.io.IOException;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.AuthorizeCallback;

import org.wildfly.security.auth.callback.AuthenticationCompleteCallback;
import org.wildfly.security.auth.callback.AvailableRealmsCallback;
import org.wildfly.security.auth.callback.EvidenceVerifyCallback;
import org.wildfly.security.auth.callback.IdentityCredentialCallback;
import org.wildfly.security.credential.BearerTokenCredential;
import org.wildfly.security.evidence.BearerTokenEvidence;
import org.wildfly.security.http.HttpAuthenticationException;
import org.wildfly.security.http.HttpConstants;
import org.wildfly.security.http.HttpServerAuthenticationMechanism;
import org.wildfly.security.http.HttpServerRequest;
import org.wildfly.security.http.HttpServerResponse;
import org.wildfly.security.mechanism._private.MechanismUtil;
import org.wildfly.security.mechanism.AuthenticationMechanismException;

/**
 * <p>A {@link HttpServerAuthenticationMechanism} capable to perform authentication based on a bearer token.
 *
 * <p>This mechanisms expects bearer tokens to be sent along with a <code>Authorization</code> request header as follows:
 *
 * <pre>
 *      GET /resource-server HTTP/1.1
 *      Host: elytron.org
 *      Authorization: Bearer hgTasdMNMMAsii
 * </pre>
 *
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
final class BearerTokenAuthenticationMechanism implements HttpServerAuthenticationMechanism {

    private static final Pattern BEARER_TOKEN_PATTERN = Pattern.compile("^Bearer *([^ ]+) *$", Pattern.CASE_INSENSITIVE);

    private final CallbackHandler callbackHandler;

    BearerTokenAuthenticationMechanism(CallbackHandler callbackHandler) {
        this.callbackHandler = callbackHandler;
    }

    @Override
    public String getMechanismName() {
        return BEARER_TOKEN;
    }

    @Override
    public void evaluateRequest(HttpServerRequest request) throws HttpAuthenticationException {
        List<String> authorizationValues = request.getRequestHeaderValues(HttpConstants.AUTHORIZATION);

        if (authorizationValues != null) {
            Matcher matcher;
            for (String current : authorizationValues) {
                if ((matcher = BEARER_TOKEN_PATTERN.matcher(current)).matches()) {
                    BearerTokenEvidence tokenEvidence = new BearerTokenEvidence(matcher.group(1));
                    EvidenceVerifyCallback verifyCallback = new EvidenceVerifyCallback(tokenEvidence);

                    handleCallback(verifyCallback);

                    if (verifyCallback.isVerified()) {
                        AuthorizeCallback authorizeCallback = new AuthorizeCallback(null, null);

                        handleCallback(authorizeCallback);

                        if (authorizeCallback.isAuthorized()) {
                            httpBearer.debugf("Token authentication successful.");
                            handleCallback(new IdentityCredentialCallback(new BearerTokenCredential(tokenEvidence.getToken()), true));
                            handleCallback(AuthenticationCompleteCallback.SUCCEEDED);
                            request.authenticationComplete();
                            return;
                        }
                    }
                    httpBearer.debugf("Token authentication failed.");
                    request.authenticationFailed("Invalid bearer token", response -> response.setStatusCode(FORBIDDEN));
                    return;
                }
            }
        }

        request.noAuthenticationInProgress(this::unauthorizedResponse);
    }

    private void handleCallback(Callback callback) throws HttpAuthenticationException {
        try {
            MechanismUtil.handleCallbacks(httpBearer, callbackHandler, callback);
        } catch (AuthenticationMechanismException e) {
            throw e.toHttpAuthenticationException();
        } catch (UnsupportedCallbackException ignored) {
            httpBearer.tracef("Unsupported callback [%s]", callback);
        }
    }

    private void unauthorizedResponse(HttpServerResponse response) throws HttpAuthenticationException {
        StringBuilder sb = new StringBuilder("Bearer");
        String realmName = getRealmName();

        if (realmName != null) {
            sb.append(" ").append(REALM).append("=\"").append(realmName).append("\"");
        }

        response.addResponseHeader(WWW_AUTHENTICATE, sb.toString());
        response.setStatusCode(UNAUTHORIZED);
    }

    private String getRealmName() throws HttpAuthenticationException {
        try {
            AvailableRealmsCallback availableRealmsCallback = new AvailableRealmsCallback();
            callbackHandler.handle(new Callback[] { availableRealmsCallback });
            String[] realmNames = availableRealmsCallback.getRealmNames();
            if (realmNames != null && realmNames.length > 0) {
                return realmNames[0];
            }
        } catch (UnsupportedCallbackException ignored) {
        } catch (IOException e) {
            throw httpBearer.mechCallbackHandlerFailedForUnknownReason(e).toHttpAuthenticationException();
        }
        return null;
    }

}
