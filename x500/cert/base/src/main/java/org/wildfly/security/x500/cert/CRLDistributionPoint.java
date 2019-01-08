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

import java.security.cert.CRLReason;
import java.util.Collection;
import java.util.EnumSet;
import java.util.List;

import org.wildfly.common.Assert;
import org.wildfly.security.asn1.ASN1Encodable;
import org.wildfly.security.asn1.ASN1Encoder;
import org.wildfly.security.x500.GeneralName;
import org.wildfly.security.x500.X500AttributeTypeAndValue;

/**
 * A single distribution point specification.
 */
public final class CRLDistributionPoint implements ASN1Encodable {
    private final DistributionPointName distributionPoint;
    private final EnumSet<CRLReason> reasons;
    private final List<GeneralName> crlIssuer;

    /**
     * Construct a new instance.
     *
     * @param distributionPoint the distribution point, or {@code null} for none
     * @param reasons the reason flags, or {@code null} if unspecified
     * @param crlIssuer the CRL issuer, or {@code null} for none
     */
    public CRLDistributionPoint(final DistributionPointName distributionPoint, final EnumSet<CRLReason> reasons, final List<GeneralName> crlIssuer) {
        this.distributionPoint = distributionPoint;
        this.reasons = reasons;
        this.crlIssuer = crlIssuer;
    }

    public void encodeTo(final ASN1Encoder encoder) {
        if (distributionPoint != null) {
            encoder.encodeImplicit(0);
            distributionPoint.encodeTo(encoder);
        }
        if (reasons != null) {
            encoder.encodeImplicit(1);
            encoder.encodeBitString(reasons);
        }
        if (crlIssuer != null) {
            encoder.encodeImplicit(2);
            encoder.startSequence();
            for (GeneralName name : crlIssuer) {
                name.encodeTo(encoder);
            }
            encoder.endSequence();
        }
    }

    /**
     * Base class of distribution point names.
     */
    public abstract static class DistributionPointName implements ASN1Encodable {
        DistributionPointName() {
        }
    }

    /**
     * A full-name distribution point name.
     */
    public static final class FullNameDistributionPointName extends DistributionPointName {
        private final List<GeneralName> fullName;

        /**
         * Construct a new instance.
         *
         * @param fullName the full name (must not be {@code null} or empty)
         */
        public FullNameDistributionPointName(final List<GeneralName> fullName) {
            Assert.checkNotNullParam("fullName", fullName);
            Assert.checkNotEmptyParam("fullName", fullName);
            this.fullName = fullName;
        }

        public void encodeTo(final ASN1Encoder encoder) {
            encoder.encodeImplicit(0);
            encoder.startSequence();
            for (GeneralName name : fullName) {
                name.encodeTo(encoder);
            }
            encoder.endSequence();
        }
    }

    /**
     * A distribution point name which is relative to a CRL issuer name.
     */
    public static final class RelativeToCRLIssuerDistributionPointName extends DistributionPointName {
        private final Collection<X500AttributeTypeAndValue> attributes;

        /**
         * Construct a new instance.
         *
         * @param attributes the attributes (must not be {@code null} or empty)
         */
        public RelativeToCRLIssuerDistributionPointName(final Collection<X500AttributeTypeAndValue> attributes) {
            Assert.checkNotNullParam("attributes", attributes);
            Assert.checkNotEmptyParam("attributes", attributes);
            this.attributes = attributes;
        }

        public void encodeTo(final ASN1Encoder encoder) {
            encoder.encodeImplicit(1);
            encoder.startSet();
            for (X500AttributeTypeAndValue attribute : attributes) {
                attribute.encodeTo(encoder);
            }
            encoder.endSet();
        }
    }
}
