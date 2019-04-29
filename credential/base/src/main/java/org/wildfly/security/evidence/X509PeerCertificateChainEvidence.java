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

import java.security.Principal;
import java.security.cert.X509Certificate;

import javax.security.auth.x500.X500Principal;

import org.wildfly.common.Assert;

/**
 * A piece of evidence that is comprised of a verified peer certificate chain.
 */
public final class X509PeerCertificateChainEvidence implements AlgorithmEvidence {

    private final X509Certificate[] peerCertificateChain;
    private Principal decodedPrincipal;

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
     * Get the {@link Principal} represented by the first certificate in the chain.
     *
     * @return the {@link Principal} represented by the first certificate in the chain.
     * @deprecated Use {@link #getDefaultPrincipal()} or {@link #getDecodedPrincipal()} instead.
     */
    @Deprecated
    @Override
    public X500Principal getPrincipal() {
        return getFirstCertificate().getSubjectX500Principal();
    }

    public X500Principal getDefaultPrincipal() {
        return getFirstCertificate().getSubjectX500Principal();
    }

    public Principal getDecodedPrincipal() {
        return decodedPrincipal;
    }

    public void setDecodedPrincipal(Principal decodedPrincipal) {
        this.decodedPrincipal = decodedPrincipal;
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

    /**
     * Get the first certificate in the peer certificate chain.
     *
     * @return the first certificate in the peer certificate chain
     */
    public X509Certificate getFirstCertificate() {
        return peerCertificateChain[0];
    }

    /**
     * Get the last certificate in the peer certificate chain.
     *
     * @return the last certificate in the peer certificate chain
     */
    public X509Certificate getLastCertificate() {
        return peerCertificateChain[peerCertificateChain.length - 1];
    }


}
