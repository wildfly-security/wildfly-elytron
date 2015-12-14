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

package org.wildfly.security.x500;

import java.security.cert.X509Certificate;

import javax.security.auth.x500.X500Principal;

import org.wildfly.security.auth.server.EvidenceDecoder;
import org.wildfly.security.evidence.Evidence;
import org.wildfly.security.evidence.X509PeerCertificateChainEvidence;

/**
 * An evidence decoder which can decode an {@link X509Certificate} into an {@link X500Principal}.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class X509CertificateEvidenceDecoder implements EvidenceDecoder {

    private static final X509CertificateEvidenceDecoder INSTANCE = new X509CertificateEvidenceDecoder();

    private X509CertificateEvidenceDecoder() {
    }

    public X500Principal getPrincipalFromEvidence(final Evidence evidence) {
        if (evidence instanceof X509PeerCertificateChainEvidence) {
            return ((X509PeerCertificateChainEvidence) evidence).getFirstCertificate().getSubjectX500Principal();
        }
        return null;
    }

    /**
     * Get the singleton instance of this class.
     *
     * @return the evidence decoder instance
     */
    public static X509CertificateEvidenceDecoder getInstance() {
        return INSTANCE;
    }
}
