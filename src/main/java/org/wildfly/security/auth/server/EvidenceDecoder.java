/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2015 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.auth.server;

import org.wildfly.common.Assert;

import java.security.Principal;
import org.wildfly.security.evidence.Evidence;

/**
 * A decoder which acquires a principal from evidence.  Implementations may indicate that the evidence
 * is not understood.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public interface EvidenceDecoder {

    /**
     * Get the principal from an opaque evidence.  If this decoder cannot understand the given evidence
     * type, {@code null} is returned.
     *
     * @param evidence the evidence to decode
     * @return the principal, or {@code null} if this decoder does not understand the evidence
     */
    Principal getPrincipalFromEvidence(Evidence evidence);

    /**
     * Create an aggregated evidence decoder.  The aggregated decoder will check each evidence decoder until one
     * matches the evidence; this result will be returned.
     *
     * @param decoders the constituent decoders
     * @return the aggregated decoder
     */
    static EvidenceDecoder aggregate(final EvidenceDecoder... decoders) {
        Assert.checkNotNullParam("decoders", decoders);
        return evidence -> {
            Principal result;
            for (EvidenceDecoder decoder : decoders) {
                result = decoder.getPrincipalFromEvidence(evidence);
                if (result != null) {
                    return result;
                }
            }
            return null;
        };
    }
}
