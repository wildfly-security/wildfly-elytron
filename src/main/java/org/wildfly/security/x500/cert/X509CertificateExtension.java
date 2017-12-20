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

import java.io.IOException;
import java.io.OutputStream;
import java.security.cert.Extension;

import org.wildfly.security.asn1.ASN1Encodable;
import org.wildfly.security.asn1.DEREncoder;

/**
 * An X.509 certificate extension.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public abstract class X509CertificateExtension implements ASN1Encodable, Extension {
    private final boolean critical;

    /**
     * Construct a new instance.
     *
     * @param critical {@code true} if this extension is to be marked <em>critical</em>, {@code false} otherwise
     */
    protected X509CertificateExtension(final boolean critical) {
        this.critical = critical;
    }

    /**
     * Get the OID of this extension.
     *
     * @return the OID of this extension (must not be {@code null})
     */
    public abstract String getId();

    /**
     * Determine whether this object represents a critical extension (as defined by <a
     * href="https://tools.ietf.org/html/rfc5280">RFC 5280</a>).
     *
     * @return {@code true} if the extension is critical, {@code false} otherwise
     */
    public final boolean isCritical() {
        return critical;
    }

    public void encode(final OutputStream out) throws IOException {
        out.write(getValue());
    }

    public byte[] getValue() {
        DEREncoder encoder = new DEREncoder();
        encodeTo(encoder);
        return encoder.getEncoded();
    }
}
