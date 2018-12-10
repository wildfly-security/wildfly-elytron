/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2017 Red Hat, Inc., and individual contributors
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

import java.security.spec.AlgorithmParameterSpec;
import java.util.function.Function;

import org.wildfly.common.Assert;
import org.wildfly.security._private.ElytronMessages;
import org.wildfly.security.credential.AlgorithmCredential;
import org.wildfly.security.credential.Credential;

/**
 * Abstract base class for credential callbacks.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public abstract class AbstractCredentialCallback implements ExtendedCallback {

    private final Class<? extends Credential> credentialType;
    private final String algorithm;
    private final AlgorithmParameterSpec parameterSpec;
    private Credential credential;

    AbstractCredentialCallback(final Class<? extends Credential> credentialType, final String algorithm, final AlgorithmParameterSpec parameterSpec) {
        Assert.checkNotNullParam("credentialType", credentialType);
        if (parameterSpec != null) Assert.checkNotNullParam("algorithm", algorithm);
        this.algorithm = algorithm;
        this.credentialType = credentialType;
        this.parameterSpec = parameterSpec;
    }

    /**
     * Get the acquired credential.
     *
     * @return the acquired credential, or {@code null} if it wasn't set yet.
     */
    public Credential getCredential() {
        return credential;
    }

    /**
     * Get the acquired credential, if it is set and of the given type, and if so, return the credential cast to the type.
     *
     * @param credentialType the credential type class (must not be {@code null})
     * @param <C> the credential type
     * @return the credential, or {@code null} if the criteria wasn't met
     */
    public <C extends Credential> C getCredential(Class<C> credentialType) {
        return applyToCredential(credentialType, Function.identity());
    }

    /**
     * Get the acquired credential, if it is set and of the given type and algorithm, and if so, return the credential cast to the type.
     *
     * @param credentialType the credential type class (must not be {@code null})
     * @param algorithmName the algorithm name
     * @param <C> the credential type
     * @return the credential, or {@code null} if the criteria are not met
     */
    public <C extends Credential> C getCredential(Class<C> credentialType, String algorithmName) {
        return applyToCredential(credentialType, algorithmName, Function.identity());
    }

    /**
     * Get the acquired credential, if it is set and of the given type, algorithm, and parameters, and if so, return the credential cast to the type.
     *
     * @param credentialType the credential type class (must not be {@code null})
     * @param algorithmName the algorithm name
     * @param parameterSpec the parameter specification to match, or {@code null} if any parameters are allowed or parameters are not used by
     *  the credential type
     * @param <C> the credential type
     * @return the credential, or {@code null} if the criteria are not met
     */
    public <C extends Credential> C getCredential(Class<C> credentialType, String algorithmName, AlgorithmParameterSpec parameterSpec) {
        return applyToCredential(credentialType, algorithmName, parameterSpec, Function.identity());
    }

    /**
     * Apply the given function to the acquired credential, if it is set and of the given type.  By calling this method,
     * it is possible to apply transformations to the stored credential without failing if the credential was not set.
     *
     * @param credentialType the credential type class (must not be {@code null})
     * @param function the function to apply (must not be {@code null})
     * @param <C> the credential type
     * @param <R> the return type
     * @return the result of the function, or {@code null} if the criteria are not met
     */
    public <C extends Credential, R> R applyToCredential(Class<C> credentialType, Function<C, R> function) {
        final Credential credential = this.credential;
        return credential == null ? null : credential.castAndApply(credentialType, function);
    }

    /**
     * Apply the given function to the acquired credential, if it is set and of the given type and algorithm.  By calling this method,
     * it is possible to apply transformations to the stored credential without failing if the credential was not set.
     *
     * @param credentialType the credential type class (must not be {@code null})
     * @param algorithmName the algorithm name
     * @param function the function to apply (must not be {@code null})
     * @param <C> the credential type
     * @param <R> the return type
     * @return the result of the function, or {@code null} if the criteria are not met
     */
    public <C extends Credential, R> R applyToCredential(Class<C> credentialType, String algorithmName, Function<C, R> function) {
        final Credential credential = this.credential;
        return credential == null ? null : credential.castAndApply(credentialType, algorithmName, function);
    }

    /**
     * Apply the given function to the acquired credential, if it is set and of the given type and algorithm.  By calling this method,
     * it is possible to apply transformations to the stored credential without failing if the credential was not set.
     *
     * @param credentialType the credential type class (must not be {@code null})
     * @param algorithmName the algorithm name
     * @param parameterSpec the parameter specification to match, or {@code null} if any parameters are allowed or parameters are not used by
     *  the credential type
     * @param function the function to apply (must not be {@code null})
     * @param <C> the credential type
     * @param <R> the return type
     * @return the result of the function, or {@code null} if the criteria are not met
     */
    public <C extends Credential, R> R applyToCredential(Class<C> credentialType, String algorithmName, AlgorithmParameterSpec parameterSpec, Function<C, R> function) {
        final Credential credential = this.credential;
        return credential == null ? null : credential.castAndApply(credentialType, algorithmName, parameterSpec, function);
    }

    /**
     * Set the credential.  The credential must be of the supported type and algorithm.
     *
     * @param credential the credential, or {@code null} to indicate that no credential is available
     * @throws IllegalArgumentException if the given credential is not supported
     */
    public void setCredential(final Credential credential) {
        if (credential != null && ! isCredentialSupported(credential)) {
            throw ElytronMessages.log.credentialNotSupported();
        }
        this.credential = credential;
    }

    /**
     * Determine whether the given credential type is supported.  Will be {@code false} if the credential type requires
     * an algorithm name; in this case, use {@link #isCredentialTypeSupported(Class, String)} instead.
     *
     * @param credentialType the credential type (must not be {@code null})
     * @return {@code true} if the credential type is supported, {@code false} otherwise
     */
    public boolean isCredentialTypeSupported(final Class<? extends Credential> credentialType) {
        return isCredentialTypeSupported(credentialType, null);
    }

    /**
     * Determine whether the given credential type is supported for the given algorithm name.
     *
     * @param credentialType the credential type (must not be {@code null})
     * @param algorithmName the algorithm name, or {@code null} to indicate that no algorithm name will be available
     * @return {@code true} if the credential type is supported, {@code false} otherwise
     */
    public boolean isCredentialTypeSupported(final Class<? extends Credential> credentialType, final String algorithmName) {
        Assert.checkNotNullParam("credentialType", credentialType);
        return this.credentialType.isAssignableFrom(credentialType) && (algorithm == null || AlgorithmCredential.class.isAssignableFrom(credentialType) && algorithm.equals(algorithmName));
    }

    /**
     * Determine whether the given credential type is supported for the given algorithm name.
     *
     * @param credentialType the credential type (must not be {@code null})
     * @param algorithmName the algorithm name, or {@code null} to indicate that no algorithm name will be available
     * @param parameterSpec the parameters, or {@code null} if no parameters are present in the credential
     * @return {@code true} if the credential type is supported, {@code false} otherwise
     */
    public boolean isCredentialTypeSupported(final Class<? extends Credential> credentialType, final String algorithmName, final AlgorithmParameterSpec parameterSpec) {
        Assert.checkNotNullParam("credentialType", credentialType);
        return isCredentialTypeSupported(credentialType, algorithmName) && (this.parameterSpec == null || this.parameterSpec.equals(parameterSpec));
    }

    /**
     * Determine whether the given credential can be set on this callback.
     *
     * @param credential the credential (must not be {@code null})
     * @return {@code true} if the credential matches the type and optional algorithm of this callback, {@code false} otherwise
     */
    public boolean isCredentialSupported(final Credential credential) {
        Assert.checkNotNullParam("credential", credential);
        return credential.castAs(credentialType, algorithm, parameterSpec) != null;
    }

    /**
     * Get the supported credential type.
     *
     * @return the supported credential type (not {@code null})
     */
    public Class<? extends Credential> getCredentialType() {
        return credentialType;
    }

    /**
     * Get the algorithm name, if any.
     *
     * @return the algorithm name, or {@code null} if any algorithm is suitable or the credential
     *  type does not use algorithm names
     */
    public String getAlgorithm() {
        return algorithm;
    }

    /**
     * Get the parameter specification, if any.
     *
     * @return the parameter specification, or {@code null} if any parameters are suitable or the credential type
     *  does not use parameters
     */
    public AlgorithmParameterSpec getParameterSpec() {
        return parameterSpec;
    }

    public boolean needsInformation() {
        return true;
    }
}
