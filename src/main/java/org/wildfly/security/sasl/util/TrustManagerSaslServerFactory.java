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

package org.wildfly.security.sasl.util;

import static org.wildfly.security.sasl.entity.TrustedAuthority.CertificateTrustedAuthority;

import java.security.GeneralSecurityException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import javax.net.ssl.X509TrustManager;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;

import org.wildfly.security.FixedSecurityFactory;
import org.wildfly.security.SecurityFactory;
import org.wildfly.security.auth.callback.EvidenceVerifyCallback;
import org.wildfly.security.auth.callback.TrustedAuthoritiesCallback;
import org.wildfly.security.evidence.Evidence;
import org.wildfly.security.evidence.X509PeerCertificateChainEvidence;
import org.wildfly.security.sasl.entity.TrustedAuthority;
import org.wildfly.security.ssl.SSLUtils;

/**
 * A {@link SaslServerFactory} which sets the trust manager that should be used for trust verification.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public final class TrustManagerSaslServerFactory extends AbstractDelegatingSaslServerFactory {

    private final SecurityFactory<X509TrustManager> trustManagerFactory;

    /**
     * Construct a new instance.
     *
     * @param delegate the delegate SASL server factory
     * @param trustManager the trust manager to use or {@code null} if the default trust manager should be used
     */
    public TrustManagerSaslServerFactory(final SaslServerFactory delegate, final X509TrustManager trustManager) {
        super(delegate);
        if (trustManager == null) {
            this.trustManagerFactory = SSLUtils.getDefaultX509TrustManagerSecurityFactory();
        } else {
            this.trustManagerFactory = new FixedSecurityFactory<>(trustManager);
        }
    }

    public SaslServer createSaslServer(final String mechanism, final String protocol, final String serverName, final Map<String, ?> props, final CallbackHandler cbh) throws SaslException {
        return delegate.createSaslServer(mechanism, protocol, serverName, props, callbacks -> {
            ArrayList<Callback> list = new ArrayList<>(Arrays.asList(callbacks));
            final Iterator<Callback> iterator = list.iterator();
            while (iterator.hasNext()) {
                Callback callback = iterator.next();
                if (callback instanceof TrustedAuthoritiesCallback) {
                    final X509TrustManager trustManager = getTrustManager();
                    ((TrustedAuthoritiesCallback) callback).setTrustedAuthorities(getTrustedAuthorities(trustManager.getAcceptedIssuers()));
                    iterator.remove();
                } else if (callback instanceof EvidenceVerifyCallback) {
                    final EvidenceVerifyCallback evidenceVerifyCallback = (EvidenceVerifyCallback) callback;
                    final Evidence evidence = evidenceVerifyCallback.getEvidence();
                    if (evidence instanceof X509PeerCertificateChainEvidence) {
                        final X509TrustManager trustManager = getTrustManager();
                        final X509PeerCertificateChainEvidence peerCertificateChainEvidence = (X509PeerCertificateChainEvidence) evidence;
                        try {
                            trustManager.checkClientTrusted(peerCertificateChainEvidence.getPeerCertificateChain(), peerCertificateChainEvidence.getAlgorithm());
                            evidenceVerifyCallback.setVerified(true);
                        } catch (CertificateException e) {
                        }
                        iterator.remove();
                    }
                }
            }
            if (! list.isEmpty()) {
                cbh.handle(list.toArray(new Callback[list.size()]));
            }
        });
    }

    private List<TrustedAuthority> getTrustedAuthorities(X509Certificate[] acceptedIssuers) {
        if (acceptedIssuers == null) {
            return null;
        }
        List<TrustedAuthority> trustedAuthorities = new ArrayList<TrustedAuthority>(acceptedIssuers.length);
        for (X509Certificate acceptedIssuer : acceptedIssuers) {
            trustedAuthorities.add(new CertificateTrustedAuthority(acceptedIssuer));
        }
        return trustedAuthorities;
    }

    private X509TrustManager getTrustManager() throws SaslException {
        try {
            return trustManagerFactory.create();
        } catch (GeneralSecurityException e) {
            throw new SaslException(e.getMessage(), e);
        }
    }
}
