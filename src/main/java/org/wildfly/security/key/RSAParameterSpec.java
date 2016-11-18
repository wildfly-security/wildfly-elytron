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

package org.wildfly.security.key;

import java.math.BigInteger;
import java.security.interfaces.RSAKey;
import java.security.spec.AlgorithmParameterSpec;

import org.wildfly.common.Assert;

/**
 * Algorithm parameter specification for RSA keys.  RSA keys do not support a parameter object, but it does in fact
 * have a parameter: the modulus.  The methods on {@link KeyUtil} will therefore treat this class as the parameter type.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class RSAParameterSpec implements AlgorithmParameterSpec {
    private final BigInteger modulus;

    /**
     * Construct a new instance.
     *
     * @param modulus the modulus (must not be {@code null})
     */
    public RSAParameterSpec(final BigInteger modulus) {
        Assert.checkNotNullParam("modulus", modulus);
        this.modulus = modulus;
    }

    /**
     * Construct a new instance.
     *
     * @param rsaKey the RSA key from which the modulus should be acquired (must not be {@code null})
     */
    public RSAParameterSpec(final RSAKey rsaKey) {
        this(Assert.checkNotNullParam("rsaKey", rsaKey).getModulus());
    }

    /**
     * Get the modulus.
     *
     * @return the modulus (not {@code null})
     */
    public BigInteger getModulus() {
        return modulus;
    }

    public boolean equals(final Object obj) {
        return this == obj || obj instanceof RSAParameterSpec && modulus.equals(((RSAParameterSpec) obj).getModulus());
    }

    public int hashCode() {
        return modulus.hashCode();
    }
}
