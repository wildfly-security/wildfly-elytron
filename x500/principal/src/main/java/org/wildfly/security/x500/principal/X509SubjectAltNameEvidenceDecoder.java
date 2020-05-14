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

import java.security.Principal;
import java.security.cert.CertificateParsingException;
import java.util.Collection;
import java.util.List;

import org.wildfly.security.auth.principal.NamePrincipal;
import org.wildfly.security.auth.server.EvidenceDecoder;
import org.wildfly.security.evidence.Evidence;
import org.wildfly.security.evidence.X509PeerCertificateChainEvidence;

/**
 * An evidence decoder that derives the principal that should be associated with the given
 * {@code X509PeerCertificateChainEvidence} from an X.509 subject alternative name from the
 * first certificate in the given evidence.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 * @since 1.10.0
 */
public final class X509SubjectAltNameEvidenceDecoder implements EvidenceDecoder {

    private final int altNametype;
    private final int segment;

    /**
     * Construct a new instance.
     *
     * @param altNameType the subject alternative name type to decode. Must be one of:
     *                    <ul>
     *                        <li>{@code GeneralName.RFC_822_NAME}</li>
     *                        <li>{@code GeneralName.DNS_NAME}</li>
     *                        <li>{@code GeneralName.DIRECTORY_NAME}</li>
     *                        <li>{@code GeneralName.URI_NAME}</li>
     *                        <li>{@code GeneralName.IP_ADDRESS}</li>
     *                        <li>{@code GeneralName.REGISTERED_ID}</li>
     *                    </ul>
     */
    public X509SubjectAltNameEvidenceDecoder(final int altNameType) {
        this(altNameType, 0);
    }

    /**
     * Construct a new instance.
     *
     * @param altNameType the subject alternative name type to decode. Must be one of:
     *                    <ul>
     *                        <li>{@code GeneralName.RFC_822_NAME}</li>
     *                        <li>{@code GeneralName.DNS_NAME}</li>
     *                        <li>{@code GeneralName.DIRECTORY_NAME}</li>
     *                        <li>{@code GeneralName.URI_NAME}</li>
     *                        <li>{@code GeneralName.IP_ADDRESS}</li>
     *                        <li>{@code GeneralName.REGISTERED_ID}</li>
     *                    </ul>
     * @param segment the 0-based occurrence of the subject alternative name to map, used when there is more than one subject
     *                alternative name of the given {@code altNameType}
     */
    public X509SubjectAltNameEvidenceDecoder(final int altNameType, final int segment) {
        this.altNametype = altNameType;
        this.segment = segment;
    }

    public Principal getPrincipal(final Evidence evidence) {
        if (! (evidence instanceof X509PeerCertificateChainEvidence)) {
            return null;
        }
        try {
            Collection<List<?>> subjectAltNames = ((X509PeerCertificateChainEvidence) evidence).getFirstCertificate().getSubjectAlternativeNames();
            if (subjectAltNames != null) {
                int typeOccurrence = 0;
                for (List<?> subjectAltName : subjectAltNames) {
                    int type = (Integer) subjectAltName.get(0);
                    if (type == altNametype) {
                        if (typeOccurrence == segment) {
                            return new NamePrincipal((String) subjectAltName.get(1));
                        }
                        typeOccurrence++;
                    }
                }
            }
            return null;
        } catch (CertificateParsingException e) {
            return null;
        }
    }
}
