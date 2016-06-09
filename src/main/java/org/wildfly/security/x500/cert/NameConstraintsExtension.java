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
import org.wildfly.security.x500.GeneralName;
import org.wildfly.security.x500.X500;

/**
 * A name constraints extension as defined by <a href="https://tools.ietf.org/html/rfc5280#section-4.2.1.10">RFC 5280 § 4.2.1.10</a>.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class NameConstraintsExtension extends X509CertificateExtension {
    private final List<GeneralSubtree> permittedSubtrees;
    private final List<GeneralSubtree> excludedSubtrees;

    /**
     * Construct a new instance.
     *
     * @param permittedSubtrees the permitted subtrees list (must not be {@code null}, may be empty)
     * @param excludedSubtrees the excluded subtrees list (must not be {@code null}, may be empty)
     */
    public NameConstraintsExtension(final List<GeneralSubtree> permittedSubtrees, final List<GeneralSubtree> excludedSubtrees) {
        super(true);
        Assert.checkNotNullParam("permittedSubtrees", permittedSubtrees);
        Assert.checkNotNullParam("excludedSubtrees", excludedSubtrees);
        this.permittedSubtrees = permittedSubtrees;
        this.excludedSubtrees = excludedSubtrees;
    }

    public String getId() {
        return X500.OID_CE_NAME_CONSTRAINTS;
    }

    public void encodeTo(final ASN1Encoder encoder) {
        encoder.startSequence();
        if (! permittedSubtrees.isEmpty()) {
            encoder.encodeImplicit(0);
            encoder.startSequence();
            for (GeneralSubtree subtree : permittedSubtrees) {
                subtree.encodeTo(encoder);
            }
            encoder.endSequence();
        }
        if (! excludedSubtrees.isEmpty()) {
            encoder.encodeImplicit(1);
            encoder.startSequence();
            for (GeneralSubtree subtree : excludedSubtrees) {
                subtree.encodeTo(encoder);
            }
            encoder.endSequence();
        }
        encoder.endSequence();
    }

    /**
     * A general subtree for a name constraint.
     */
    public static final class GeneralSubtree implements ASN1Encodable {
        private final GeneralName base;
        private final int minimumDistance;
        private final int maximumDistance;

        /**
         * Construct a new instance.
         *
         * @param base the base name (must not be {@code null})
         * @param minimumDistance the minimum distance (must be >= 0)
         * @param maximumDistance the maximum distance (must be -1 indicating "not specified" or >= {@code minimumDistance})
         */
        public GeneralSubtree(final GeneralName base, final int minimumDistance, final int maximumDistance) {
            this.base = base;
            Assert.checkMinimumParameter("minimumDistance", 0, minimumDistance);
            if (maximumDistance != -1) {
                Assert.checkMinimumParameter("maximumDistance", minimumDistance, maximumDistance);
            }
            this.minimumDistance = minimumDistance;
            this.maximumDistance = maximumDistance;
        }

        public void encodeTo(final ASN1Encoder encoder) {
            encoder.startSequence();
            base.encodeTo(encoder);
            if (minimumDistance > 0) {
                encoder.encodeImplicit(0);
                encoder.encodeInteger(minimumDistance);
            }
            if (maximumDistance >= 0) {
                encoder.encodeImplicit(1);
                encoder.encodeInteger(maximumDistance);
            }
        }
    }
}
