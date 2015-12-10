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

package org.wildfly.security.evidence;

import java.security.cert.X509Certificate;

import org.wildfly.common.Assert;

/**
 * A piece of evidence that is comprised of a verified peer certificate chain.
 */
public final class X509PeerCertificateChainEvidence implements AlgorithmEvidence {

    private final X509Certificate[] peerCertificateChain;

    /**
     * Construct a new instance.
     *
     * @param peerCertificateChain the peer certificate chain to use (must not be {@code null})
     */
    public X509PeerCertificateChainEvidence(final X509Certificate... peerCertificateChain) {
        Assert.checkNotNullParam("peerCertificateChain", peerCertificateChain);
        this.peerCertificateChain = peerCertificateChain;
    }

    /**
     * Get the peer certificate chain.
     *
     * @return the peer certificate chain (not {@code null})
     */
    public X509Certificate[] getPeerCertificateChain() {
        return peerCertificateChain;
    }

    /**
     * Get the certificate public key algorithm.
     *
     * @return the certificate public key algorithm (not {@code null})
     */
    public String getAlgorithm() {
        return getFirstCertificate().getPublicKey().getAlgorithm();
    }

    public X509Certificate getFirstCertificate() {
        return peerCertificateChain[0];
    }

    public X509Certificate getLastCertificate() {
        return peerCertificateChain[peerCertificateChain.length - 1];
    }
}
