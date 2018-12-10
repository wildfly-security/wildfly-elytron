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
import org.wildfly.security.asn1.ASN1Encodable;
import org.wildfly.security.asn1.ASN1Encoder;
import org.wildfly.security.x500.X500;

/**
 * The policy mappings extension as defined by <a href="https://tools.ietf.org/html/rfc5280#section-4.2.1.5">RFC 5280 § 4.2.1.5</a>.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class PolicyMappingsExtension extends X509CertificateExtension {
    private final List<PolicyMapping> policyMappings;

    /**
     * Construct a new instance.
     *
     * @param critical {@code true} if the extension should be marked critical (recommended) or {@code false} otherwise
     * @param policyMappings the list of policy mappings (must not be {@code null})
     */
    public PolicyMappingsExtension(final boolean critical, final List<PolicyMapping> policyMappings) {
        super(critical);
        Assert.checkNotNullParam("policyMappings", policyMappings);
        this.policyMappings = policyMappings;
    }

    public String getId() {
        return X500.OID_CE_POLICY_MAPPINGS;
    }

    public void encodeTo(final ASN1Encoder encoder) {
        encoder.startSequence();
        for (PolicyMapping policyMapping : policyMappings) {
            policyMapping.encodeTo(encoder);
        }
        encoder.endSequence();
    }

    /**
     * A single policy mapping.
     */
    public static final class PolicyMapping implements ASN1Encodable {
        private final String issuerDomainPolicyOid;
        private final String subjectDomainPolicyOid;

        /**
         * Construct a new instance.
         *
         * @param issuerDomainPolicyOid the OID of the issuer domain policy (must not be {@code null})
         * @param subjectDomainPolicyOid the OID of the subject domain policy (must not be {@code null})
         */
        public PolicyMapping(final String issuerDomainPolicyOid, final String subjectDomainPolicyOid) {
            Assert.checkNotNullParam("issuerDomainPolicyOid", issuerDomainPolicyOid);
            Assert.checkNotNullParam("subjectDomainPolicyOid", subjectDomainPolicyOid);
            this.issuerDomainPolicyOid = issuerDomainPolicyOid;
            this.subjectDomainPolicyOid = subjectDomainPolicyOid;
        }

        /**
         * Get the issuer domain policy OID.
         *
         * @return the issuer domain policy OID
         */
        public String getIssuerDomainPolicyOid() {
            return issuerDomainPolicyOid;
        }

        /**
         * Get the subject domain policy OID.
         *
         * @return the subject domain policy OID
         */
        public String getSubjectDomainPolicyOid() {
            return subjectDomainPolicyOid;
        }

        public void encodeTo(final ASN1Encoder encoder) {
            encoder.startSequence();
            encoder.encodeObjectIdentifier(issuerDomainPolicyOid);
            encoder.encodeObjectIdentifier(subjectDomainPolicyOid);
            encoder.endSequence();
        }
    }
}
