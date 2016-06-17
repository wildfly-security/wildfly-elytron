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

import org.wildfly.security.asn1.ASN1Encoder;
import org.wildfly.security.x500.X500;

/**
 * A policy constraints extension as defined by <a href="https://tools.ietf.org/html/rfc5280#section-4.2.1.11">RFC 5280 § 4.2.1.11</a>.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class PolicyConstraintsExtension extends X509CertificateExtension {
    private final int requireExplicitPolicy;
    private final int inhibitPolicyMapping;

    /**
     * Construct a new instance.
     *
     * @param requireExplicitPolicy the number of additional certificates that may appear in the path before an explicit policy is required for the entire path (-1 to indicate that no such policy exists)
     * @param inhibitPolicyMapping the number of additional certificates that may appear in the path before the policy mapping is no longer permitted (-1 to indicate that no such policy exists)
     */
    public PolicyConstraintsExtension(final int requireExplicitPolicy, final int inhibitPolicyMapping) {
        super(true);
        this.requireExplicitPolicy = requireExplicitPolicy;
        this.inhibitPolicyMapping = inhibitPolicyMapping;
    }

    public String getId() {
        return X500.OID_CE_POLICY_CONSTRAINTS;
    }

    public void encodeTo(final ASN1Encoder encoder) {
        encoder.startSequence();
        if (requireExplicitPolicy >= 0) {
            encoder.encodeImplicit(0);
            encoder.encodeInteger(requireExplicitPolicy);
        }
        if (inhibitPolicyMapping >= 0) {
            encoder.encodeImplicit(1);
            encoder.encodeInteger(inhibitPolicyMapping);
        }
        encoder.endSequence();
    }
}
