/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2019 Red Hat, Inc., and individual contributors
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

import java.security.Principal;
import java.util.function.Function;

import org.wildfly.common.Assert;
import org.wildfly.security.evidence.Evidence;

/**
 * A decoder for extracting a principal from evidence.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 * @since 1.10.0
 */
@FunctionalInterface
public interface EvidenceDecoder extends Function<Evidence, Principal> {

    /**
     * Get the principal from the given evidence. If this decoder does not understand the given evidence,
     * {@code null} is returned.
     *
     * @param evidence the evidence to decode
     * @return the principal, or {@code null} if this decoder does not understand the evidence
     */
    Principal getPrincipal(Evidence evidence);

    default Principal apply(Evidence evidence) {
        return getPrincipal(evidence);
    }

    /**
     * Create an aggregated evidence decoder. The aggregated decoder will try each evidence decoder until one
     * returns a {@code non-null} value. If all the evidence decoders return {@code null}, then {@code null}
     * will be returned.
     *
     * @param decoders the constituent decoders
     * @return the aggregated decoder
     */
    static EvidenceDecoder aggregate(final EvidenceDecoder... decoders) {
        Assert.checkNotNullParam("decoders", decoders);
        return evidence -> {
            Principal result;
            for (EvidenceDecoder decoder : decoders) {
                result = decoder.getPrincipal(evidence);
                if (result != null) {
                    return result;
                }
            }
            return null;
        };
    }

}
