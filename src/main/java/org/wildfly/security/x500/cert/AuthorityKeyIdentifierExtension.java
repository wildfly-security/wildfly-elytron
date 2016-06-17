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

import java.math.BigInteger;
import java.util.List;

import org.wildfly.security.asn1.ASN1Encoder;
import org.wildfly.security.x500.GeneralName;
import org.wildfly.security.x500.X500;

/**
 * Authority key identifier extension as defined by <a href="https://tools.ietf.org/html/rfc5280#section-4.2.1.1">RFC 5280 § 4.2.1.1</a>.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class AuthorityKeyIdentifierExtension extends X509CertificateExtension {

    private final byte[] keyIdentifier;
    private final List<GeneralName> generalNames;
    private final BigInteger serialNumber;

    /**
     * Construct a new instance.
     *
     * @param keyIdentifier the key identifier to specify, or {@code null} to leave it out
     * @param generalNames the list of general names to specify, or {@code null} to leave it out
     * @param serialNumber the serial number to specify, or {@code null} to leave it out
     */
    public AuthorityKeyIdentifierExtension(final byte[] keyIdentifier, final List<GeneralName> generalNames, final BigInteger serialNumber) {
        super(false);
        this.keyIdentifier = keyIdentifier;
        this.generalNames = generalNames;
        this.serialNumber = serialNumber;
    }

    public String getId() {
        return X500.OID_CE_AUTHORITY_KEY_IDENTIFIER;
    }

    public void encodeTo(final ASN1Encoder encoder) {
        encoder.startSequence();
        if (keyIdentifier != null) {
            encoder.encodeImplicit(0);
            encoder.encodeOctetString(keyIdentifier);
        }
        if (generalNames != null && ! generalNames.isEmpty()) {
            encoder.encodeImplicit(1);
            encoder.startSequence();
            for (GeneralName generalName : generalNames) {
                generalName.encodeTo(encoder);
            }
            encoder.endSequence();
        }
        if (serialNumber != null) {
            encoder.encodeImplicit(2);
            encoder.encodeInteger(serialNumber);
        }
        encoder.endSequence();
    }
}
