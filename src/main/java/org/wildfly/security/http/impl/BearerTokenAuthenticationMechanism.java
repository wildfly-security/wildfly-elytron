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

package org.wildfly.security.http.impl;

import static org.wildfly.security._private.ElytronMessages.log;
import static org.wildfly.security.http.HttpConstants.BEARER_TOKEN;

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.AuthorizeCallback;

import org.wildfly.security.auth.callback.AuthenticationCompleteCallback;
import org.wildfly.security.auth.callback.EvidenceVerifyCallback;
import org.wildfly.security.auth.callback.IdentityCredentialCallback;
import org.wildfly.security.credential.BearerTokenCredential;
import org.wildfly.security.evidence.BearerTokenEvidence;
import org.wildfly.security.http.HttpAuthenticationException;
import org.wildfly.security.http.HttpServerAuthenticationMechanism;
import org.wildfly.security.http.HttpServerRequest;
import org.wildfly.security.mechanism.AuthenticationMechanismException;
import org.wildfly.security.mechanism.MechanismUtil;

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
class BearerTokenAuthenticationMechanism implements HttpServerAuthenticationMechanism {

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
        List<String> authorizationValues = request.getRequestHeaderValues("Authorization");

        if (authorizationValues == null || authorizationValues.isEmpty()) {
            request.authenticationFailed("Bearer token required", response -> response.setStatusCode(401));
            return;
        } else if (authorizationValues.size() > 1) {
            request.authenticationFailed("Multiple Authorization headers found", response -> response.setStatusCode(400));
            return;
        }

        String authorizationValue = authorizationValues.get(0);
        Matcher matcher = BEARER_TOKEN_PATTERN.matcher(authorizationValue);

        if (!matcher.matches()) {
            request.authenticationFailed("Authorization is not Bearer", response -> response.setStatusCode(400));
            return;
        }

        BearerTokenEvidence tokenEvidence = new BearerTokenEvidence(matcher.group(1));
        EvidenceVerifyCallback verifyCallback = new EvidenceVerifyCallback(tokenEvidence);

        handleCallback(verifyCallback);

        if (verifyCallback.isVerified()) {
            AuthorizeCallback authorizeCallback = new AuthorizeCallback(null, null);

            handleCallback(authorizeCallback);

            if (authorizeCallback.isAuthorized()) {
                handleCallback(new IdentityCredentialCallback(new BearerTokenCredential(tokenEvidence.getToken()), true));
                handleCallback(AuthenticationCompleteCallback.SUCCEEDED);
                request.authenticationComplete();
                return;
            }
        }

        request.authenticationFailed("Invalid bearer token", response -> response.setStatusCode(403));
    }

    private void handleCallback(Callback callback) throws HttpAuthenticationException {
        try {
            MechanismUtil.handleCallbacks(BEARER_TOKEN, callbackHandler, callback);
        } catch (AuthenticationMechanismException e) {
            throw e.toHttpAuthenticationException();
        } catch (UnsupportedCallbackException ignored) {
            log.tracef("Unsupported callback [%s]", callback);
        }
    }
}
