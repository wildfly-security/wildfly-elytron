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
import org.wildfly.security.password.spec.IteratedSaltedPasswordAlgorithmSpec;

/**
 * A SCRAM-digest password, used by the SCRAM family of SASL mechanisms.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public interface ScramDigestPassword extends OneWayPassword {

    /**
     * The algorithm "scram-sha-1".
     */
    String ALGORITHM_SCRAM_SHA_1 = "scram-sha-1";

    /**
     * The algorithm "scram-sha-256".
     */
    String ALGORITHM_SCRAM_SHA_256 = "scram-sha-256";

    /**
     * The algorithm "scram-sha-384".
     */
    String ALGORITHM_SCRAM_SHA_384 = "scram-sha-384";

    /**
     * The algorithm "scram-sha-512".
     */
    String ALGORITHM_SCRAM_SHA_512 = "scram-sha-512";

    /**
     * The default salt size for this password type.
     */
    int DEFAULT_SALT_SIZE = 12;

    /**
     * The default iteration count for this password type.
     */
    int DEFAULT_ITERATION_COUNT = 20000;

    /**
     * Get the digest represented by this {@linkplain Password password}.
     *
     * @return the digest represented by this {@linkplain Password password}
     */
    byte[] getDigest();

    /**
     * Get the salt used to generate the digest.
     *
     * @return the salt used to generate the digest
     */
    byte[] getSalt();

    /**
     * Get the iteration count used to generate the digest.
     *
     * @return the iteration count used to generate the digest
     */
    int getIterationCount();

    default IteratedSaltedPasswordAlgorithmSpec getParameterSpec() {
        return new IteratedSaltedPasswordAlgorithmSpec(getIterationCount(), getSalt());
    }

    /**
     * Creates and returns a copy of this {@link Password}.
     *
     * @return a copy of this {@link Password}.
     */
    ScramDigestPassword clone();

    /**
     * Create a raw implementation of this password type.  No validation of the content is performed, and the password
     * must be "adopted" in to a {@link PasswordFactory} (via the {@link PasswordFactory#translate(Password)} method)
     * before it can be validated and used to verify guesses.
     *
     * @param algorithm the algorithm name
     * @param digest the digest
     * @param salt the salt
     * @param iterationCount the iteration count
     * @return the raw password implementation
     */
    static ScramDigestPassword createRaw(String algorithm, byte[] digest, byte[] salt, int iterationCount) {
        Assert.checkNotNullParam("algorithm", algorithm);
        Assert.checkNotNullParam("digest", digest);
        Assert.checkNotNullParam("salt", salt);
        return new RawScramDigestPassword(algorithm, digest.clone(), salt.clone(), iterationCount);
    }
}