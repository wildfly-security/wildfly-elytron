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

import java.security.spec.AlgorithmParameterSpec;

import org.wildfly.common.Assert;

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
     * Get the default algorithm parameters of the any type from this credential.
     *
     * @return the parameter specification, or {@code null} if no parameters are present or available or the given type
     * was not supported by this credential
     */
    default AlgorithmParameterSpec getParameters() {
        return getParameters(AlgorithmParameterSpec.class);
    }

    /**
     * Get the algorithm parameters of the given type from this credential.
     *
     * @param paramSpecClass the parameter specification class (must not be {@code null})
     * @return the parameter specification, or {@code null} if no parameters are present or available or the given type
     * was not supported by this credential
     */
    default <P extends AlgorithmParameterSpec> P getParameters(Class<P> paramSpecClass) {
        Assert.checkNotNullParam("paramSpecClass", paramSpecClass);
        return null;
    }

    /**
     * Determine whether this credential instance supports any algorithm parameter type.
     *
     * @return {@code true} if parameters are supported, {@code false} otherwise
     */
    default boolean supportsParameters() {
        return supportsParameters(AlgorithmParameterSpec.class);
    }

    /**
     * Determine whether this credential instance supports the given algorithm parameter type.
     *
     * @param paramSpecClass the parameter specification class (must not be {@code null})
     * @return {@code true} if the parameter type is supported, {@code false} otherwise
     */
    default boolean supportsParameters(Class<? extends AlgorithmParameterSpec> paramSpecClass) {
        return false;
    }

    /**
     * Determine whether this credential implies the given parameters.  The default implementation returns
     * {@code false} always.
     *
     * @param parameterSpec the parameters to test for (must not be {@code null})
     * @return {@code true} if the given parameters match this credential, {@code false} otherwise
     */
    default boolean impliesParameters(AlgorithmParameterSpec parameterSpec) {
        Assert.checkNotNullParam("parameterSpec", parameterSpec);
        return false;
    }

    /**
     * Determine whether the other credential's parameters are implied by this one.
     *
     * @param other the other credential (must not be {@code null})
     * @return {@code true} if the credentials have matching parameters, {@code false} otherwise
     */
    default boolean impliesSameParameters(AlgorithmCredential other) {
        Assert.checkNotNullParam("other", other);
        final AlgorithmParameterSpec parameters = other.getParameters();
        return parameters == null ? ! supportsParameters() : impliesParameters(parameters);
    }

    /**
     * Creates and returns a copy of this {@link Credential}.
     *
     * @return a copy of this {@link Credential}.
     */
    AlgorithmCredential clone();

    default boolean matches(Credential other) {
        return other instanceof AlgorithmCredential && matches((AlgorithmCredential) other);
    }

    default boolean matches(AlgorithmCredential other) {
        return other != null && other.getClass() == getClass() && getAlgorithm().equals(other.getAlgorithm()) && impliesSameParameters(other);
    }

    default boolean matches(Class<? extends Credential> credentialType, String algorithmName, AlgorithmParameterSpec parameterSpec) {
        return credentialType.isInstance(this) && (algorithmName == null || algorithmName.equals(getAlgorithm())) && (parameterSpec == null || impliesParameters(parameterSpec));
    }
}
