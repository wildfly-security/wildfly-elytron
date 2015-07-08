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

package org.wildfly.security.password.interfaces;

import org.wildfly.common.Assert;
import org.wildfly.security.password.OneWayPassword;
import org.wildfly.security.password.Password;

/**
 * A one-time password, used by the OTP SASL mechanism.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public interface OneTimePassword extends OneWayPassword {

    /**
     * The algorithm name "otp-md5".
     */
    String ALGORITHM_OTP_MD5 = "otp-md5";

    /**
     * The algorithm name "otp-sha1".
     */
    String ALGORITHM_OTP_SHA1 = "otp-sha1";

    /**
     * The constant size of the hash, in bytes.
     */
    int OTP_HASH_SIZE = 8;

    /**
     * Get the hash represented by this {@linkplain Password password}.
     *
     * @return the hash represented by this {@linkplain Password password}
     */
    byte[] getHash();

    /**
     * Get the seed used to generate the hash.
     *
     * @return the seed used to generate the hash
     */
    byte[] getSeed();

    /**
     * Get the sequence number used to generate the hash.
     *
     * @return the sequence number used to generate the hash
     */
    int getSequenceNumber();

    /**
     * Create a raw implementation of this password type.  No validation of the content is performed, and the password
     * must be "adopted" in to a {@link PasswordFactory} (via the {@link PasswordFactory#translate(Password)} method)
     * before it can be validated and used to verify guesses.
     *
     * @param algorithm the algorithm name
     * @param hash the hash
     * @param seed the seed
     * @param sequenceNumber the sequence number
     * @return the raw password implementation
     */
    static OneTimePassword createRaw(String algorithm, byte[] hash, byte[] seed, int sequenceNumber) {
        Assert.checkNotNullParam("hash", hash);
        Assert.checkNotNullParam("seed", seed);
        Assert.checkNotNullParam("algorithm", algorithm);
        return new RawOneTimePassword(algorithm, hash.clone(), seed.clone(), sequenceNumber);
    }
}
