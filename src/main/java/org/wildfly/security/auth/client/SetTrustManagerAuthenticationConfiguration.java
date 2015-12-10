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

package org.wildfly.security.auth.client;

import static org.wildfly.security._private.ElytronMessages.log;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateException;

import javax.net.ssl.X509TrustManager;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.wildfly.security.SecurityFactory;
import org.wildfly.security.auth.callback.EvidenceVerifyCallback;
import org.wildfly.security.evidence.Evidence;
import org.wildfly.security.evidence.X509PeerCertificateChainEvidence;

/**
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
class SetTrustManagerAuthenticationConfiguration extends AuthenticationConfiguration {

    private final SecurityFactory<X509TrustManager> trustManagerFactory;

    SetTrustManagerAuthenticationConfiguration(final AuthenticationConfiguration parent, final SecurityFactory<X509TrustManager> trustManagerFactory) {
        super(parent);
        this.trustManagerFactory = trustManagerFactory;
    }

    AuthenticationConfiguration reparent(final AuthenticationConfiguration newParent) {
        return new SetTrustManagerAuthenticationConfiguration(newParent, trustManagerFactory);
    }

    SecurityFactory<X509TrustManager> getX509TrustManagerFactory() {
        return trustManagerFactory;
    }

    void handleCallback(final Callback[] callbacks, final int index) throws IOException, UnsupportedCallbackException {
        final Callback callback = callbacks[index];
        if (callback instanceof EvidenceVerifyCallback) {
            final EvidenceVerifyCallback evidenceVerifyCallback = (EvidenceVerifyCallback) callback;
            final Evidence evidence = evidenceVerifyCallback.getEvidence();
            if (evidence instanceof X509PeerCertificateChainEvidence) {
                final X509PeerCertificateChainEvidence peerCertificateChainEvidence = (X509PeerCertificateChainEvidence) evidence;
                X509TrustManager trustManager;
                try {
                    trustManager = trustManagerFactory.create();
                } catch (GeneralSecurityException e) {
                    throw log.unableToCreateTrustManager(e);
                }
                try {
                    trustManager.checkServerTrusted(peerCertificateChainEvidence.getPeerCertificateChain(), peerCertificateChainEvidence.getAlgorithm());
                    evidenceVerifyCallback.setVerified(true);
                } catch (CertificateException e) {
                }
                return;
            }
        }
        super.handleCallback(callbacks, index);
    }
}
