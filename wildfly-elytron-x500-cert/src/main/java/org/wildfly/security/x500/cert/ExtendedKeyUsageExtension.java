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

package org.wildfly.security.x500.cert;

import java.util.List;

import org.wildfly.common.Assert;
import org.wildfly.security.asn1.ASN1Encoder;
import org.wildfly.security.x500.X500;

/**
 * An extended key usage extension as defined by <a href="https://tools.ietf.org/html/rfc5280#section-4.2.1.12">RFC 5280 § 4.2.1.12</a>.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class ExtendedKeyUsageExtension extends X509CertificateExtension {
    private final List<String> keyPurposeIds;

    /**
     * Construct a new instance.  The key purpose OIDs should typically be chosen from the {@link X500 X500.OID_KP_*} constants.
     *
     * @param critical {@code true} to mark this extension as critical, {@code false} to mark it as non-critical
     * @param keyPurposeIds the key purpose OIDs list (must not be {@code null} or empty)
     */
    public ExtendedKeyUsageExtension(final boolean critical, final List<String> keyPurposeIds) {
        super(critical);
        Assert.checkNotNullParam("keyPurposeIds", keyPurposeIds);
        Assert.checkNotEmptyParam("keyPurposeIds", keyPurposeIds);
        this.keyPurposeIds = keyPurposeIds;
    }

    public String getId() {
        return X500.OID_CE_EXT_KEY_USAGE;
    }

    public void encodeTo(final ASN1Encoder encoder) {
        encoder.startSequence();
        for (String keyPurposeId : keyPurposeIds) {
            encoder.encodeObjectIdentifier(keyPurposeId);
        }
        encoder.endSequence();
    }
}
