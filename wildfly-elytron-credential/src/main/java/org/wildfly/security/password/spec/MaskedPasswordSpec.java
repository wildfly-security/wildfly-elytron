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

import static org.wildfly.common.math.HashMath.multiHashOrdered;

import java.util.Arrays;

import org.wildfly.common.Assert;

/**
 * A password specification for a two-way password which is masked.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class MaskedPasswordSpec implements PasswordSpec {
    private final char[] initialKeyMaterial;
    private final int iterationCount;
    private final byte[] salt;
    private final byte[] maskedPasswordBytes;

    /**
     * Construct a new instance.
     *
     * @param initialKeyMaterial the initial key material (must not be {@code null})
     * @param iterationCount the iteration count
     * @param salt the salt bytes (must not be {@code null})
     * @param maskedPasswordBytes the masked password bytes (must not be {@code null})
     */
    public MaskedPasswordSpec(final char[] initialKeyMaterial, final int iterationCount, final byte[] salt, final byte[] maskedPasswordBytes) {
        Assert.checkNotNullParam("initialKeyMaterial", initialKeyMaterial);
        Assert.checkNotNullParam("salt", salt);
        Assert.checkNotNullParam("maskedPasswordBytes", maskedPasswordBytes);
        this.initialKeyMaterial = initialKeyMaterial;
        this.iterationCount = iterationCount;
        this.salt = salt;
        this.maskedPasswordBytes = maskedPasswordBytes;
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
     * Get the masked password bytes.
     *
     * @return the masked password bytes (must not be {@code null})
     */
    public byte[] getMaskedPasswordBytes() {
        return maskedPasswordBytes;
    }

    @Override
    public boolean equals(Object other) {
        if (! (other instanceof MaskedPasswordSpec)) return false;
        MaskedPasswordSpec o = (MaskedPasswordSpec) other;
        return Arrays.equals(initialKeyMaterial, o.initialKeyMaterial) && iterationCount == o.iterationCount && salt == o.salt && maskedPasswordBytes == o.maskedPasswordBytes;
    }

    @Override
    public int hashCode() {
        return multiHashOrdered(multiHashOrdered(multiHashOrdered(Arrays.hashCode(initialKeyMaterial), iterationCount), Arrays.hashCode(salt)), Arrays.hashCode(maskedPasswordBytes));
    }
}
