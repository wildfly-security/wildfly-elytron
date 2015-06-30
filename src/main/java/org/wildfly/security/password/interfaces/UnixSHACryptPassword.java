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

import org.wildfly.common.Assert;
import org.wildfly.security.password.OneWayPassword;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactory;

/**
 * The UNIX modular-crypt SHA crypt algorithm.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public interface UnixSHACryptPassword extends OneWayPassword {

    /**
     * The algorithm name "crypt-sha-256".
     */
    String ALGORITHM_CRYPT_SHA_256 = "crypt-sha-256";

    /**
     * The algorithm name "crypt-sha-512".
     */
    String ALGORITHM_CRYPT_SHA_512 = "crypt-sha-512";

    /**
     * The maximum salt size of this algorithm.
     */
    int SALT_SIZE = 16;

    /**
     * The default iteration count of this algorithm.
     */
    int DEFAULT_ITERATION_COUNT = 5000;

    /**
     * The salt used during the hashing of this password. Should have at most 16 bytes.
     * @return the salt
     */
    byte[] getSalt();

    /**
     * The final hash, based on the password, salt and iteration count
     * @return the hash
     */
    byte[] getHash();

    /**
     * The number of iterations to perform when hashing the password. Should be bigger than 1,000 and lower than 999,999,999.
     * The default value is 5,000
     * @return  the number of iterations to perform
     */
    int getIterationCount();

    /**
     * Create a raw implementation of this password type.  No validation of the content is performed, and the password
     * must be "adopted" in to a {@link PasswordFactory} (via the {@link PasswordFactory#translate(Password)} method)
     * before it can be validated and used to verify guesses.
     *
     * @param algorithm the algorithm name
     * @param salt the salt
     * @param hash the hash
     * @param iterationCount the iteration count
     * @return the raw password implementation
     */
    static UnixSHACryptPassword createRaw(String algorithm, byte[] salt, byte[] hash, int iterationCount) {
        Assert.checkNotNullParam("algorithm", algorithm);
        Assert.checkNotNullParam("salt", salt);
        Assert.checkNotNullParam("hash", hash);
        return new RawUnixSHACryptPassword(algorithm, salt, hash, iterationCount);
    }
}
