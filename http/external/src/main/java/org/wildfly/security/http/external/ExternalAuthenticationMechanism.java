/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2020 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.http.external;

import static org.wildfly.security.http.HttpConstants.EXTERNAL_NAME;
import static org.wildfly.security.http.HttpConstants.FORBIDDEN;
import static org.wildfly.security.mechanism._private.ElytronMessages.httpExternal;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.AuthorizeCallback;

import org.wildfly.security.auth.callback.AuthenticationCompleteCallback;
import org.wildfly.security.http.HttpAuthenticationException;
import org.wildfly.security.http.HttpServerAuthenticationMechanism;
import org.wildfly.security.http.HttpServerRequest;
import org.wildfly.security.mechanism.AuthenticationMechanismException;
import org.wildfly.security.mechanism._private.MechanismUtil;

/**
 * The EXTERNAL authentication mechanism.
 *
 * @author <a href="mailto:aabdelsa@redhat.com">Ashley Abdel-Sayed</a>
 */
public class ExternalAuthenticationMechanism implements HttpServerAuthenticationMechanism {

    private final CallbackHandler callbackHandler;

    ExternalAuthenticationMechanism(CallbackHandler callbackHandler) {
        this.callbackHandler = callbackHandler;
    }

    /**
     * @see org.wildfly.security.http.HttpServerAuthenticationMechanism#getMechanismName()
     */
    @Override
    public String getMechanismName() {
        return EXTERNAL_NAME;
    }

    @Override
    public void evaluateRequest(HttpServerRequest request) throws HttpAuthenticationException {

        String remoteUser = request.getRemoteUser();
        if (remoteUser == null) {
            request.noAuthenticationInProgress();
            return;
        }

        if (authorize(remoteUser)) {
            succeed(request);
        } else {
            fail(request);
        }

    }

    private boolean authorize(String username) throws HttpAuthenticationException {
        AuthorizeCallback authorizeCallback = new AuthorizeCallback(username, username);
        try {
            MechanismUtil.handleCallbacks(httpExternal, callbackHandler, authorizeCallback);
            return authorizeCallback.isAuthorized();
        } catch (AuthenticationMechanismException e) {
            throw e.toHttpAuthenticationException();
        } catch (UnsupportedCallbackException e) {
            throw httpExternal.mechCallbackHandlerFailedForUnknownReason(e).toHttpAuthenticationException();
        }
    }

    private void succeed(HttpServerRequest request) throws HttpAuthenticationException {
        try {
            MechanismUtil.handleCallbacks(httpExternal, callbackHandler, AuthenticationCompleteCallback.SUCCEEDED);
            request.authenticationComplete();
        } catch (AuthenticationMechanismException e) {
            throw e.toHttpAuthenticationException();
        } catch (UnsupportedCallbackException e) {
            throw httpExternal.mechCallbackHandlerFailedForUnknownReason(e).toHttpAuthenticationException();
        }
    }

    private void fail(HttpServerRequest request) throws HttpAuthenticationException {
        try {
            MechanismUtil.handleCallbacks(httpExternal, callbackHandler, AuthenticationCompleteCallback.FAILED);
            request.authenticationFailed(httpExternal.authenticationFailed(), response -> response.setStatusCode(FORBIDDEN));
        } catch (AuthenticationMechanismException e) {
            throw e.toHttpAuthenticationException();
        } catch (UnsupportedCallbackException e) {
            throw httpExternal.mechCallbackHandlerFailedForUnknownReason(e).toHttpAuthenticationException();
        }
    }
}
