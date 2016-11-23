/*
 * JBoss, Home of Professional Open Source
 * Copyright 2013 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.password.interfaces;

import java.security.spec.AlgorithmParameterSpec;

import org.wildfly.common.Assert;
import org.wildfly.security.password.OneWayPassword;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.spec.SaltedPasswordAlgorithmSpec;

/**
 * The traditional UNIX DES crypt password algorithm.
 */
public interface UnixDESCryptPassword extends OneWayPassword {

    /**
     * The algorithm name "crypt-des".
     */
    String ALGORITHM_CRYPT_DES = "crypt-des";

    /**
     * Get the salt of this password as a {@code short}.
     *
     * @return the salt
     */
    short getSalt();

    /**
     * Get the crypt bytes, not including the salt.
     *
     * @return the crypt bytes
     */
    byte[] getHash();

    default SaltedPasswordAlgorithmSpec getParameterSpec() {
        final int salt = getSalt();
        byte[] saltBytes = new byte[2];
        // Big-endian format
        saltBytes[0] = (byte) (salt >>> 8 & 0xff);
        saltBytes[1] = (byte) (salt & 0xff);
        return new SaltedPasswordAlgorithmSpec(saltBytes);
    }

    default boolean impliesParameters(AlgorithmParameterSpec parameterSpec) {
        Assert.checkNotNullParam("parameterSpec", parameterSpec);
        return parameterSpec.equals(getParameterSpec());
    }

    /**
     * Creates and returns a copy of this {@link Password}.
     *
     * @return a copy of this {@link Password}.
     */
    UnixDESCryptPassword clone();

    /**
     * Create a raw implementation of this password type.  No validation of the content is performed, and the password
     * must be "adopted" in to a {@link PasswordFactory} (via the {@link PasswordFactory#translate(Password)} method)
     * before it can be validated and used to verify guesses.
     *
     * @param algorithm the algorithm name
     * @param salt the salt
     * @param hash the hash
     * @return the raw password implementation
     */
    static UnixDESCryptPassword createRaw(String algorithm, short salt, byte[] hash) {
        Assert.checkNotNullParam("algorithm", algorithm);
        Assert.checkNotNullParam("hash", hash);
        return new RawUnixDESCryptPassword(algorithm, salt, hash);
    }
}
