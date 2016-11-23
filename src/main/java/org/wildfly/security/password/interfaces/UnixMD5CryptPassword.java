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

package org.wildfly.security.password.interfaces;

import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

import org.wildfly.common.Assert;
import org.wildfly.security.password.OneWayPassword;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.spec.IteratedPasswordAlgorithmSpec;
import org.wildfly.security.password.spec.IteratedSaltedPasswordAlgorithmSpec;
import org.wildfly.security.password.spec.SaltedPasswordAlgorithmSpec;

/**
 * The UNIX modular-crypt MD5 crypt algorithm.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public interface UnixMD5CryptPassword extends OneWayPassword {

    /**
     * The algorithm name "crypt-md5".
     */
    String ALGORITHM_CRYPT_MD5 = "crypt-md5";

    /**
     * The maximum salt size.
     */
    int SALT_SIZE = 8;

    /**
     * The fixed iteration count.
     */
    int ITERATION_COUNT = 1000;

    /**
     * Get the salt component of this password.
     *
     * @return the salt component
     */
    byte[] getSalt();

    /**
     * Get the hash component of this password.
     *
     * @return the hash component
     */
    byte[] getHash();

    default SaltedPasswordAlgorithmSpec getParameterSpec() {
        return new SaltedPasswordAlgorithmSpec(getSalt());
    }

    default boolean impliesParameters(AlgorithmParameterSpec parameterSpec) {
        Assert.checkNotNullParam("parameterSpec", parameterSpec);
        if (parameterSpec instanceof IteratedSaltedPasswordAlgorithmSpec) {
            final IteratedSaltedPasswordAlgorithmSpec spec = (IteratedSaltedPasswordAlgorithmSpec) parameterSpec;
            // iteration count has to match exactly since it's not flexible for this algorithm
            return ITERATION_COUNT == spec.getIterationCount() && Arrays.equals(getSalt(), spec.getSalt());
        } else if (parameterSpec instanceof SaltedPasswordAlgorithmSpec) {
            return Arrays.equals(getSalt(), ((SaltedPasswordAlgorithmSpec) parameterSpec).getSalt());
        } else if (parameterSpec instanceof IteratedPasswordAlgorithmSpec) {
            // iteration count has to match exactly since it's not flexible for this algorithm
            return ITERATION_COUNT == ((IteratedPasswordAlgorithmSpec) parameterSpec).getIterationCount();
        } else {
            return false;
        }
    }

    /**
     * Creates and returns a copy of this {@link Password}.
     *
     * @return a copy of this {@link Password}.
     */
    UnixMD5CryptPassword clone();

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
    static UnixMD5CryptPassword createRaw(String algorithm, byte[] salt, byte[] hash) {
        Assert.checkNotNullParam("algorithm", algorithm);
        Assert.checkNotNullParam("salt", salt);
        Assert.checkNotNullParam("hash", hash);
        return new RawUnixMD5CryptPassword(algorithm, salt, hash);
    }
}
