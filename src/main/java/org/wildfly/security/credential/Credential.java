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

package org.wildfly.security.credential;

import org.wildfly.common.Assert;
import org.wildfly.security.evidence.AlgorithmEvidence;
import org.wildfly.security.evidence.Evidence;

/**
 * A credential is a piece of information that can be used to verify or produce evidence.
 */
public interface Credential {

    /**
     * Determine whether this credential can, generally speaking, verify the given evidence type.
     *
     * @param evidenceClass the evidence type (must not be {@code null})
     * @param algorithmName the evidence algorithm name (may be {@code null} if the type of evidence does not support
     * algorithm names)
     *
     * @return {@code true} if the evidence can be verified by this credential, {@code false} otherwise
     */
    default boolean canVerify(Class<? extends Evidence> evidenceClass, String algorithmName) {
        Assert.checkNotNullParam("evidenceClass", evidenceClass);
        return false;
    }

    /**
     * Determine whether this credential can verify the given evidence.
     *
     * @param evidence the evidence (must not be {@code null})
     *
     * @return {@code true} if the evidence can be verified by this credential, {@code false} otherwise
     */
    default boolean canVerify(Evidence evidence) {
        Assert.checkNotNullParam("evidence", evidence);
        return canVerify(evidence.getClass(), evidence instanceof AlgorithmEvidence ? ((AlgorithmEvidence) evidence).getAlgorithm() : null);
    }

    /**
     * Verify the given evidence.
     *
     * @param evidence the evidence to verify (must not be {@code null})
     *
     * @return {@code true} if the evidence is verified, {@code false} otherwise
     */
    default boolean verify(Evidence evidence) {
        Assert.checkNotNullParam("evidence", evidence);
        return false;
    }
}
