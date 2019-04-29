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
package org.wildfly.security.auth.callback;

import java.util.function.Function;

import javax.security.auth.callback.Callback;

import org.wildfly.security.evidence.Evidence;

/**
 * A server-side {@link Callback} to pass the decoded evidence principal from the callback handler
 * to the authentication mechanism.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 * @since 1.10.0
 */
public class EvidenceDecodePrincipalCallback implements ExtendedCallback {

    private final Evidence evidence;

    /**
     * Construct a new instance of this {@link Callback}.
     *
     * @param evidence the evidence to be decoded
     */
    public EvidenceDecodePrincipalCallback(final Evidence evidence) {
        this.evidence = evidence;
    }

    /**
     * Get the evidence being decoded.
     *
     * @return the evidence being decoded
     */
    public Evidence getEvidence() {
        return evidence;
    }

    /**
     * Get the acquired evidence, if it is set and of the given type, and if so, return the evidence cast to the type.
     *
     * @param evidenceType the evidence type class (must not be {@code null})
     * @param <C> the evidence type
     * @return the evidence, or {@code null} if the criteria wasn't met
     */
    public <C extends Evidence> C getEvidence(Class<C> evidenceType) {
        return applyToEvidence(evidenceType, Function.identity());
    }

    /**
     * Get the acquired evidence, if it is set and of the given type and algorithm, and if so, return the evidence cast to the type.
     *
     * @param evidenceType the evidence type class (must not be {@code null})
     * @param algorithmName the algorithm name
     * @param <C> the evidence type
     * @return the evidence, or {@code null} if the criteria are not met
     */
    public <C extends Evidence> C getEvidence(Class<C> evidenceType, String algorithmName) {
        return applyToEvidence(evidenceType, algorithmName, Function.identity());
    }

    /**
     * Apply the given function to the acquired evidence, if it is set and of the given type.
     *
     * @param evidenceType the evidence type class (must not be {@code null})
     * @param function the function to apply (must not be {@code null})
     * @param <C> the evidence type
     * @param <R> the return type
     * @return the result of the function, or {@code null} if the criteria are not met
     */
    public <C extends Evidence, R> R applyToEvidence(Class<C> evidenceType, Function<C, R> function) {
        final Evidence evidence = this.evidence;
        return evidence == null ? null : evidence.castAndApply(evidenceType, function);
    }

    /**
     * Apply the given function to the acquired evidence, if it is set and of the given type and algorithm.
     *
     * @param evidenceType the evidence type class (must not be {@code null})
     * @param algorithmName the algorithm name
     * @param function the function to apply (must not be {@code null})
     * @param <C> the evidence type
     * @param <R> the return type
     * @return the result of the function, or {@code null} if the criteria are not met
     */
    public <C extends Evidence, R> R applyToEvidence(Class<C> evidenceType, String algorithmName, Function<C, R> function) {
        final Evidence evidence = this.evidence;
        return evidence == null ? null : evidence.castAndApply(evidenceType, algorithmName, function);
    }

}
