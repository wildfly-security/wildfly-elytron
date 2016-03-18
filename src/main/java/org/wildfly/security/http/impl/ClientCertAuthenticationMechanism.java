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
import static org.wildfly.security.ssl.SSLUtils.SSL_SESSION_IDENTITY_KEY;

import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.wildfly.security._private.ElytronMessages;
import org.wildfly.security.auth.callback.AuthenticationCompleteCallback;
import org.wildfly.security.auth.callback.EvidenceVerifyCallback;
import org.wildfly.security.auth.callback.SecurityIdentityCallback;
import org.wildfly.security.auth.server.SecurityIdentity;
import org.wildfly.security.evidence.X509PeerCertificateChainEvidence;
import org.wildfly.security.http.HttpAuthenticationException;
import org.wildfly.security.http.HttpServerAuthenticationMechanism;
import org.wildfly.security.http.HttpServerRequest;

/**
 * The CLIENT_CERT authentication mechanism.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class ClientCertAuthenticationMechanism implements HttpServerAuthenticationMechanism {

    private final CallbackHandler callbackHandler;

    ClientCertAuthenticationMechanism(CallbackHandler callbackHandler) {
        this.callbackHandler = callbackHandler;
    }

    @Override
    public String getMechanismName() {
        return CLIENT_CERT_NAME;
    }

    @Override
    public void evaluateRequest(HttpServerRequest request) throws HttpAuthenticationException {
        SSLSession sslSession = request.getSSLSession();
        if (sslSession == null) {
            request.noAuthenticationInProgress();
            return;
        }

        SecurityIdentity securityIdentity = (SecurityIdentity) sslSession.getValue(SSL_SESSION_IDENTITY_KEY);
        if (securityIdentity != null) {
            // TODO We need to check this is applicable for our domain and use a 'converted' value.
            request.authenticationComplete(securityIdentity);
            return;
        }

        final X509Certificate[] peerX509Certificates;
        try {
            Certificate[] peerCertificates = sslSession.getPeerCertificates();
            peerX509Certificates = new X509Certificate[peerCertificates.length];
            for (int i=0;i<peerCertificates.length; i++) {
                if (peerCertificates[i] instanceof X509Certificate) {
                    peerX509Certificates[i] = (X509Certificate) peerCertificates[i];
                } else {
                    request.noAuthenticationInProgress();
                    return;
                }
            }
        } catch (SSLPeerUnverifiedException e) {
            ElytronMessages.log.trace("Peer not verified.");
            request.noAuthenticationInProgress();
            return;
        }

        final X509PeerCertificateChainEvidence evidence = new X509PeerCertificateChainEvidence(peerX509Certificates);

        EvidenceVerifyCallback evc = new EvidenceVerifyCallback(evidence);
        boolean authenticated = false;

        try {
            callbackHandler.handle(new Callback[] { evc });
            authenticated = evc.isVerified();
        } catch (IOException e) {
            throw new HttpAuthenticationException(e);
        } catch (UnsupportedCallbackException e) {}

        try {
            if (authenticated) {
                SecurityIdentityCallback securityIdentityCallback = new SecurityIdentityCallback();
                callbackHandler.handle(new Callback[] { AuthenticationCompleteCallback.SUCCEEDED, securityIdentityCallback });

                request.authenticationComplete(securityIdentityCallback.getSecurityIdentity());
                return;
            } else {
                callbackHandler.handle(new Callback[] { AuthenticationCompleteCallback.FAILED });
                request.authenticationFailed(log.authenticationFailed(CLIENT_CERT_NAME));
                return;
            }
        } catch (IOException | UnsupportedCallbackException e) {
            throw new HttpAuthenticationException(e);
        }

        // Note: We deliberately do not cache this latest SecurityIdentity in the session - many web apps could be deployed,
        // each with a different security domain.

    }

}
