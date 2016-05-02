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

import static org.wildfly.security._private.ElytronMessages.log;
import static org.wildfly.security.http.HttpConstants.CLIENT_CERT_NAME;

import javax.net.ssl.SSLSession;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.wildfly.security.auth.callback.AuthenticationCompleteCallback;
import org.wildfly.security.auth.callback.SSLSessionAuthorizationCallback;
import org.wildfly.security.http.HttpAuthenticationException;
import org.wildfly.security.http.HttpServerAuthenticationMechanism;
import org.wildfly.security.http.HttpServerRequest;
import org.wildfly.security.mechanism.AuthenticationMechanismException;
import org.wildfly.security.mechanism.MechanismUtil;

/**
 * The CLIENT_CERT authentication mechanism.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class ClientCertAuthenticationMechanism implements HttpServerAuthenticationMechanism {

    private final CallbackHandler callbackHandler;

    /**
     * Construct a new instance of the {@code ClientCertAuthenticationMechanism} mechanism.
     *
     * @param callbackHandler the {@link CallbackHandler} to use to verify the supplied credentials and to notify to establish the current identity.
     */
    ClientCertAuthenticationMechanism(CallbackHandler callbackHandler) {
        this.callbackHandler = callbackHandler;
    }

    /**
     * @see org.wildfly.security.http.HttpServerAuthenticationMechanism#getMechanismName()
     */
    @Override
    public String getMechanismName() {
        return CLIENT_CERT_NAME;
    }

    /**
     * @see org.wildfly.security.http.HttpServerAuthenticationMechanism#evaluateRequest(org.wildfly.security.http.HttpServerRequest)
     */
    @Override
    public void evaluateRequest(HttpServerRequest request) throws HttpAuthenticationException {
        SSLSession sslSession = request.getSSLSession();
        if (sslSession == null) {
            request.noAuthenticationInProgress();
            return;
        }

        final SSLSessionAuthorizationCallback callback = new SSLSessionAuthorizationCallback(sslSession);
        try {
            MechanismUtil.handleCallbacks(CLIENT_CERT_NAME, callbackHandler, callback);
        } catch (AuthenticationMechanismException e) {
            throw e.toHttpAuthenticationException();
        } catch (UnsupportedCallbackException e) {
            throw log.mechCallbackHandlerFailedForUnknownReason(CLIENT_CERT_NAME, e).toHttpAuthenticationException();
        }

        if (callback.isAuthorized()) try {
            MechanismUtil.handleCallbacks(CLIENT_CERT_NAME, callbackHandler, AuthenticationCompleteCallback.SUCCEEDED);
            request.authenticationComplete(null);
        } catch (AuthenticationMechanismException e) {
            throw e.toHttpAuthenticationException();
        } catch (UnsupportedCallbackException ignored) {
            // ignored
        } else try {
            MechanismUtil.handleCallbacks(CLIENT_CERT_NAME, callbackHandler, AuthenticationCompleteCallback.FAILED);
            request.authenticationFailed(log.authenticationFailed(CLIENT_CERT_NAME));
        } catch (AuthenticationMechanismException e) {
            throw e.toHttpAuthenticationException();
        } catch (UnsupportedCallbackException ignored) {
            // ignored
        }
    }

}
