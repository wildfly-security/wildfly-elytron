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
 * A BSD-style DES "crypt" password.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public interface BSDUnixDESCryptPassword extends OneWayPassword {

    /**
     * The algorithm name.
     */
    String ALGORITHM_BSD_CRYPT_DES = "bsd-crypt-des";

    /**
     * The constant size of the hash, in bytes.
     */
    int BSD_CRYPT_DES_HASH_SIZE = 8;

    /**
     * The constant size of the salt, in bytes.
     */
    int BSD_CRYPT_DES_SALT_SIZE = 3;

    /**
     * The default iteration count.
     */
    int DEFAULT_ITERATION_COUNT = 5001;

    /**
     * Get the iteration count of this password.
     *
     * @return the iteration count
     */
    int getIterationCount();

    /**
     * Get the salt segment of this password as an {@code int} value.
     *
     * @return the salt segment
     */
    int getSalt();

    /**
     * Get the hash segment of this password.
     *
     * @return the hash segment
     */
    byte[] getHash();

    /**
     * Create a raw implementation of this password type.  No validation of the content is performed, and the password
     * must be "adopted" in to a {@link PasswordFactory} (via the {@link PasswordFactory#translate(Password)} method)
     * before it can be validated and used to verify guesses.
     *
     * @param algorithm the algorithm name
     * @param hash the hash
     * @param salt the salt
     * @param iterationCount the iteration count
     * @return the raw password implementation
     */
    static BSDUnixDESCryptPassword createRaw(String algorithm, byte[] hash, int salt, int iterationCount) {
        Assert.checkNotNullParam("hash", hash);
        Assert.checkNotNullParam("algorithm", algorithm);
        return new RawBSDUnixDESCryptPassword(algorithm, iterationCount, salt, hash.clone());
    }
}
