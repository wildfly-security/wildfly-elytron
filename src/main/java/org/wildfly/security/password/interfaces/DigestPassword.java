/*
 * JBoss, Home of Professional Open Source
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

import org.wildfly.common.Assert;
import org.wildfly.security.password.OneWayPassword;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.spec.DigestPasswordAlgorithmSpec;

/**
 * Digest MD5 (pre-digested) password.
 *
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public interface DigestPassword extends OneWayPassword {

    long serialVersionUID = -5424657660320310755L;

    /**
     * The algorithm name "digest-md5".
     */
    String ALGORITHM_DIGEST_MD5 = "digest-md5";

    /**
     * The algorithm name "digest-sha".
     */
    String ALGORITHM_DIGEST_SHA = "digest-sha";

    /**
     * The algorithm name "digest-sha-256".
     */
    String ALGORITHM_DIGEST_SHA_256 = "digest-sha-256";

    /**
     * The algorithm name "digest-sha-384".
     */
    String ALGORITHM_DIGEST_SHA_384 = "digest-sha-384";

    /**
     * The algorithm name "digest-sha-512".
     */
    String ALGORITHM_DIGEST_SHA_512 = "digest-sha-512";

    /**
     * The algorithm name "digest-sha-512-256". (Using SHA-512/256)
     */
    String ALGORITHM_DIGEST_SHA_512_256 = "digest-sha-512-256";

    /**
     * Get the username this {@link Password} is associated with.
     * <p>
     * Generally a {@link Password} should not need to know this information but this is an integral part of how the
     * representation of this {@link Password} is created.
     *
     * @return the username this {@link Password} is associated with
     */
    String getUsername();

    /**
     * Get the realm this {@link Password} is associated with.
     * <p>
     * <em>Note:</em> This is independent of the name of the realm used to obtain the {@link Password} representation, this is the value
     * used to generate the digest.
     *
     * @return the realm this {@link Password} is associated with
     */
    String getRealm();

    /**
     * Get the digest represented by this {@link Password}.
     *
     * @return the digest represented by this {@link Password}
     */
    byte[] getDigest();

    default DigestPasswordAlgorithmSpec getParameterSpec() {
        return new DigestPasswordAlgorithmSpec(getUsername(), getRealm());
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
    DigestPassword clone();

    /**
     * Create a raw implementation of this password type.  No validation of the content is performed, and the password
     * must be "adopted" in to a {@link PasswordFactory} (via the {@link PasswordFactory#translate(Password)} method)
     * before it can be validated and used to verify guesses.
     *
     * @param algorithm the algorithm name
     * @param username the user name
     * @param realm the realm
     * @param digest the digest
     * @return the raw password implementation
     */
    static DigestPassword createRaw(String algorithm, String username, String realm, byte[] digest) {
        Assert.checkNotNullParam("algorithm", algorithm);
        Assert.checkNotNullParam("username", username);
        Assert.checkNotNullParam("realm", realm);
        Assert.checkNotNullParam("digest", digest);
        return new RawDigestPassword(algorithm, username, realm, digest.clone());
    }
}
