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

import java.util.Arrays;
import java.util.EnumSet;

import org.wildfly.common.Assert;
import org.wildfly.security.asn1.ASN1Encoder;
import org.wildfly.security.x500.X500;

/**
 * Key usage extension as defined by <a href="https://tools.ietf.org/html/rfc5280#section-4.2.1.3">RFC 5280 § 4.2.1.3</a>.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class KeyUsageExtension extends X509CertificateExtension {
    private final EnumSet<KeyUsage> keyUsage;

    /**
     * Construct a new instance.
     *
     * @param keyUsage the key usage bits (must not be {@code null})
     */
    public KeyUsageExtension(final KeyUsage... keyUsage) {
        this(true, keyUsage);
    }

    /**
     * Construct a new instance.
     *
     * @param critical {@code true} to mark this extension as critical, {@code false} to mark it as non-critical
     * @param keyUsage the key usage bits (must not be {@code null})
     * @since 1.2.0
     */
    public KeyUsageExtension(final boolean critical, final KeyUsage... keyUsage) {
        super(critical);
        Assert.checkNotNullParam("keyUsage", keyUsage);
        this.keyUsage = EnumSet.copyOf(Arrays.asList(keyUsage));
    }

    public String getId() {
        return X500.OID_CE_KEY_USAGE;
    }

    public void encodeTo(final ASN1Encoder encoder) {
        encoder.encodeBitString(keyUsage);
    }
}
