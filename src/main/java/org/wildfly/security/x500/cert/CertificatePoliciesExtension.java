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
import java.util.ArrayList;
import java.util.List;

import org.wildfly.common.Assert;
import org.wildfly.security.asn1.ASN1Encodable;
import org.wildfly.security.asn1.ASN1Encoder;
import org.wildfly.security.x500.X500;

/**
 * The certificate policies extension as defined by <a href="https://tools.ietf.org/html/rfc5280#section-4.2.1.4">RFC 5280 § 4.2.1.4</a>.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class CertificatePoliciesExtension extends X509CertificateExtension {

    private final List<PolicyInformation> policyInformationList;

    /**
     * Construct a new instance.
     *
     * @param critical {@code true} to mark this extension as critical, {@code false} otherwise
     * @param policyInformationList the policy information list (must not be {@code null})
     */
    public CertificatePoliciesExtension(final boolean critical, final List<PolicyInformation> policyInformationList) {
        super(critical);
        Assert.checkNotNullParam("policyInformationList", policyInformationList);
        this.policyInformationList = policyInformationList;
    }

    public String getId() {
        return X500.OID_CE_CERTIFICATE_POLICIES;
    }

    public void encodeTo(final ASN1Encoder encoder) {
        encoder.startSequence();
        for (PolicyInformation policy : policyInformationList) {
            policy.encodeTo(encoder);
        }
        encoder.endSequence();
    }

    /**
     * Policy information for the certificate policies extension.
     */
    public static final class PolicyInformation implements ASN1Encodable {
        private final String policyIdentifier;
        private final List<PolicyQualifier> policyQualifiers;

        /**
         * Construct a new instance.
         *
         * @param policyIdentifier the policy identifier OID (must not be {@code null})
         */
        public PolicyInformation(final String policyIdentifier) {
            Assert.checkNotNullParam("policyIdentifier", policyIdentifier);
            this.policyIdentifier = policyIdentifier;
            policyQualifiers = new ArrayList<>();
        }

        public void encodeTo(final ASN1Encoder encoder) {
            encoder.startSequence();
            encoder.encodeObjectIdentifier(policyIdentifier);
            if (! policyQualifiers.isEmpty()) {
                encoder.startSequence();
                for (PolicyQualifier policyQualifier : policyQualifiers) {
                    policyQualifier.encodeTo(encoder);
                }
                encoder.endSequence();
            }
            encoder.endSequence();
        }
    }

    /**
     * A qualifier for a policy information entry.
     */
    public static final class PolicyQualifier implements ASN1Encodable {
        private final String policyQualifierId;
        private final ASN1Encodable body;

        /**
         * Construct a new instance.
         *
         * @param policyQualifierId the policy qualifier OID (must not be {@code null})
         * @param body the body of the policy extension (must not be {@code null})
         */
        public PolicyQualifier(final String policyQualifierId, final ASN1Encodable body) {
            Assert.checkNotNullParam("policyQualifierId", policyQualifierId);
            Assert.checkNotNullParam("body", body);
            this.policyQualifierId = policyQualifierId;
            this.body = body;
        }

        public void encodeTo(final ASN1Encoder encoder) {
            encoder.startSequence();
            encoder.encodeObjectIdentifier(policyQualifierId);
            body.encodeTo(encoder);
            encoder.endSequence();
        }

        /**
         * Construct a UserNotice policy qualifier.
         *
         * @param organizationText the organization text, or {@code null} to skip the NoticeReference section
         * @param noticeNumbers the notice numbers (only used if organization text is given)
         * @param explicitText explicit text for the notice, or {@code null} to skip the DisplayText section
         * @return the constructed policy qualifier
         */
        public static PolicyQualifier userNoticeQualifier(String organizationText, BigInteger[] noticeNumbers, String explicitText) {
            return new PolicyQualifier(X500.OID_QT_UNOTICE, encoder -> {
                encoder.startSequence(); // userNotice
                if (organizationText != null) {
                    encoder.startSequence(); // noticeRef
                    encoder.encodeUTF8String(organizationText);
                    encoder.startSequence(); // noticeNumbers
                    if (noticeNumbers != null) for (BigInteger noticeNumber : noticeNumbers) {
                        encoder.encodeInteger(noticeNumber);
                    }
                    encoder.endSequence(); // noticeNumbers
                    encoder.endSequence(); // noticeRef
                }
                if (explicitText != null) {
                    encoder.encodeUTF8String(explicitText);
                }
                encoder.endSequence(); // UserNotice
            });
        }

        /**
         * Construct a CPS policy qualifier.
         *
         * @param uri the CPS URI (must not be {@code null})
         * @return the constructed policy qualifier
         */
        public static PolicyQualifier cpsQualifier(String uri) {
            return new PolicyQualifier(X500.OID_QT_CPS, encoder -> encoder.encodeIA5String(uri));
        }
    }
}
