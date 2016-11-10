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

import java.util.function.Function;

/**
 * A credential which has an associated algorithm name.
 */
public interface AlgorithmCredential extends Credential {

    /**
     * Get the algorithm name associated with this credential (will never be {@code null}).
     *
     * @return the algorithm name
     */
    String getAlgorithm();

    /**
     * Creates and returns a copy of this {@link Credential}.
     *
     * @return a copy of this {@link Credential}.
     */
    AlgorithmCredential clone();

    default <C extends Credential, R> R castAndApply(Class<C> credentialType, String algorithmName, Function<C, R> function) {
        return credentialType.isInstance(this) && (algorithmName == null || algorithmName.equals(getAlgorithm())) ? function.apply(credentialType.cast(this)) : null;
    }

    default boolean matches(Credential other) {
        return other instanceof AlgorithmCredential && matches((AlgorithmCredential) other);
    }

    default boolean matches(AlgorithmCredential other) {
        return other != null && other.getClass() == getClass() && getAlgorithm().equals(other.getAlgorithm());
    }
}
