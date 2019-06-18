/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2019 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.x500.principal;

import javax.security.auth.x500.X500Principal;

import org.wildfly.security.auth.server.EvidenceDecoder;
import org.wildfly.security.evidence.Evidence;
import org.wildfly.security.evidence.X509PeerCertificateChainEvidence;

/**
 * An evidence decoder that derives the principal that should be associated with the given
 * {@code X509PeerCertificateChainEvidence} from the subject from the first certificate in
 * the given evidence, as an {@code X500Principal}.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 * @since 1.10.0
 */
public final class X500SubjectEvidenceDecoder implements EvidenceDecoder {

    public X500Principal getPrincipal(final Evidence evidence) {
        if (! (evidence instanceof X509PeerCertificateChainEvidence)) {
            return null;
        }
        return ((X509PeerCertificateChainEvidence) evidence).getFirstCertificate().getSubjectX500Principal();
    }
}
