/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2014 Red Hat, Inc., and individual contributors
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

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.Objects;

import org.wildfly.common.Assert;

/**
 * A password specification for clear passwords which are intended to be encrypted or hashed.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class EncryptablePasswordSpec implements PasswordSpec {
    private final char[] password;
    private final AlgorithmParameterSpec algorithmParameterSpec;
    private final Charset hashCharset;

    /**
     * Construct a new instance.
     *
     * @param password the password to be encrypted or hashed
     * @param algorithmParameterSpec the parameters of the algorithm to be used for encryption or hashing
     */
    public EncryptablePasswordSpec(final char[] password, final AlgorithmParameterSpec algorithmParameterSpec) {
        this(password, algorithmParameterSpec, StandardCharsets.UTF_8);
    }

    /**
     * Construct a new instance.
     *
     * @param password the password to be encrypted or hashed
     * @param algorithmParameterSpec the parameters of the algorithm to be used for encryption or hashing
     * @param hashCharset the character set used in the password representation. Uses UTF-8 by default.
     */
    public EncryptablePasswordSpec(char[] password, AlgorithmParameterSpec algorithmParameterSpec, Charset hashCharset) {
        Assert.checkNotNullParam("password", password);
        this.password = password;
        this.algorithmParameterSpec = algorithmParameterSpec;
        this.hashCharset = hashCharset == null ? StandardCharsets.UTF_8 : hashCharset;
    }

    /**
     * Get the password characters.
     *
     * @return the password characters
     */
    public char[] getPassword() {
        return password;
    }

    /**
     * Get the algorithm parameter specification.
     *
     * @return the algorithm parameter specification
     */
    public AlgorithmParameterSpec getAlgorithmParameterSpec() {
        return algorithmParameterSpec;
    }

    /**
     * Get the character set used in the password representation
     *
     * @return the character set
     */
    public Charset getHashCharset() {
        return hashCharset;
    }

    @Override
    public boolean equals(Object other) {
        if (! (other instanceof EncryptablePasswordSpec)) return false;
        EncryptablePasswordSpec o = (EncryptablePasswordSpec) other;
        return Arrays.equals(password, o.password) && Objects.equals(algorithmParameterSpec, o.algorithmParameterSpec);
    }

    @Override
    public int hashCode() {
        return multiHashOrdered(Arrays.hashCode(password), Objects.hashCode(algorithmParameterSpec));
    }
}
