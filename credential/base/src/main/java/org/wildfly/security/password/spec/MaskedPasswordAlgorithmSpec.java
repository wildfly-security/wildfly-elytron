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

package org.wildfly.security.password.spec;

import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

import org.wildfly.common.Assert;

/**
 * An algorithm specification for a two-way password which is masked.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class MaskedPasswordAlgorithmSpec implements AlgorithmParameterSpec {
    private final char[] initialKeyMaterial;
    private final int iterationCount;
    private final byte[] salt;
    private final byte[] initializationVector;

    /**
     * Construct a new instance.
     *
     * @param initialKeyMaterial the initial key material (must not be {@code null})
     * @param iterationCount the iteration count
     * @param salt the salt bytes (must not be {@code null})
     */
    public MaskedPasswordAlgorithmSpec(final char[] initialKeyMaterial, final int iterationCount, final byte[] salt) {
        Assert.checkNotNullParam("initialKeyMaterial", initialKeyMaterial);
        Assert.checkNotNullParam("salt", salt);
        this.initialKeyMaterial = initialKeyMaterial;
        this.iterationCount = iterationCount;
        this.salt = salt;
        this.initializationVector = null;
    }

    /**
     * Construct a new instance.
     *
     * @param initialKeyMaterial the initial key material (must not be {@code null})
     * @param iterationCount the iteration count
     * @param salt the salt bytes (must not be {@code null})
     * @param initializationVector the initialization vector (can be {@code null})
     */
    public MaskedPasswordAlgorithmSpec(final char[] initialKeyMaterial, final int iterationCount, final byte[] salt, final byte[] initializationVector) {
        Assert.checkNotNullParam("initialKeyMaterial", initialKeyMaterial);
        Assert.checkNotNullParam("salt", salt);
        this.initialKeyMaterial = initialKeyMaterial;
        this.iterationCount = iterationCount;
        this.salt = salt;
        this.initializationVector = initializationVector;
    }

    /**
     * Get the initial key material.
     *
     * @return the initial key material (must not be {@code null})
     */
    public char[] getInitialKeyMaterial() {
        return initialKeyMaterial;
    }

    /**
     * Get the iteration count.
     *
     * @return the iteration count
     */
    public int getIterationCount() {
        return iterationCount;
    }

    /**
     * Get the salt bytes.
     *
     * @return the salt bytes (must not be {@code null})
     */
    public byte[] getSalt() {
        return salt;
    }

    /**
     * Get the initialization vector.
     *
     * @return the initialization vector (can be {@code null})
     */
    public byte[] getInitializationVector() {
        return initializationVector;
    }


    public boolean equals(Object other) {
        if (! (other instanceof MaskedPasswordAlgorithmSpec)) return false;
        MaskedPasswordAlgorithmSpec otherSpec = (MaskedPasswordAlgorithmSpec) other;
        return otherSpec == this
            || Arrays.equals(initialKeyMaterial, otherSpec.initialKeyMaterial)
            && Arrays.equals(salt, otherSpec.salt)
            && iterationCount == otherSpec.iterationCount
            &&Arrays.equals(initializationVector, otherSpec.initializationVector);
    }

    public int hashCode() {
        return ((Arrays.hashCode(initialKeyMaterial) * 13 + iterationCount) * 13 + Arrays.hashCode(salt)) * 13 + Arrays.hashCode(initializationVector);
    }
}
