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

package org.wildfly.security.credential;

import java.security.Provider;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.function.Supplier;

import org.wildfly.common.Assert;
import org.wildfly.security._private.ElytronMessages;
import org.wildfly.security.evidence.Evidence;
import org.wildfly.security.evidence.X509PeerCertificateChainEvidence;

abstract class AbstractX509CertificateChainCredential implements X509CertificateChainCredential {

    final X509Certificate[] certificateChain;

    AbstractX509CertificateChainCredential(X509Certificate... certificateChain) {
        Assert.checkNotNullParam("certificateChain", certificateChain);
        if (certificateChain.length > 0) {
            this.certificateChain = certificateChain.clone();
            final int length = this.certificateChain.length;
            for (int i = 0; i < length; i++) {
                Assert.checkNotNullArrayParam("certificateChain", i, this.certificateChain[i]);
            }
        } else {
            throw ElytronMessages.log.certificateChainIsEmpty();
        }
    }

    public boolean canVerify(final Class<? extends Evidence> evidenceClass, final String algorithmName) {
        return evidenceClass == X509PeerCertificateChainEvidence.class && getAlgorithm().equals(algorithmName);
    }

    public boolean verify(final Evidence evidence) {
        if (evidence instanceof X509PeerCertificateChainEvidence) {
            final X509PeerCertificateChainEvidence peerCertificateChainEvidence = (X509PeerCertificateChainEvidence) evidence;
            try {
                return getAlgorithm().equals(peerCertificateChainEvidence.getAlgorithm()) && Arrays.equals(getFirstCertificate().getEncoded(), peerCertificateChainEvidence.getFirstCertificate().getEncoded());
            } catch (CertificateEncodingException e) {
            }
        }
        return false;
    }

    public boolean verify(final Supplier<Provider[]> providerSupplier, final Evidence evidence) {
        return verify(evidence);
    }

    public String getAlgorithm() {
        return getFirstCertificate().getPublicKey().getAlgorithm();
    }

    public X509Certificate[] getCertificateChain() {
        return certificateChain.clone();
    }

    public X509Certificate getFirstCertificate() {
        return certificateChain[0];
    }

    public X509Certificate getLastCertificate() {
        return certificateChain[certificateChain.length - 1];
    }
}
