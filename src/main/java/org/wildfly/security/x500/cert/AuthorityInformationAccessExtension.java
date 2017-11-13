/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2017 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.x500.cert;

import java.util.List;

import org.wildfly.common.Assert;
import org.wildfly.security.asn1.ASN1Encoder;
import org.wildfly.security.x500.X500;

/**
 * The authority information access extension as defined by <a href="https://tools.ietf.org/html/rfc5280#section-4.2.2.1">RFC 5280 § 4.2.2.1</a>.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public final class AuthorityInformationAccessExtension extends X509CertificateExtension {

    private final List<AccessDescription> accessDescriptions;

    /**
     * Construct a new instance.
     *
     * @param accessDescriptions the list of access descriptions (must not be {@code null})
     */
    public AuthorityInformationAccessExtension(final List<AccessDescription> accessDescriptions) {
        super(false);
        Assert.checkNotNullParam("accessDescriptions", accessDescriptions);
        this.accessDescriptions = accessDescriptions;
    }

    public String getId() {
        return X500.OID_PE_AUTHORITY_INFO_ACCESS;
    }

    public void encodeTo(final ASN1Encoder encoder) {
        encoder.startSequence();
        for (AccessDescription accessDescription : accessDescriptions) {
            accessDescription.encodeTo(encoder);
        }
        encoder.endSequence();
    }

}
