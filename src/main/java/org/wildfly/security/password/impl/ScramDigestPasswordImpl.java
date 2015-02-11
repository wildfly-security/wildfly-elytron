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

package org.wildfly.security.password.impl;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.wildfly.security.password.PasswordUtil;
import org.wildfly.security.password.interfaces.ScramDigestPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.password.spec.EncryptablePasswordSpec;
import org.wildfly.security.password.spec.HashedPasswordAlgorithmSpec;
import org.wildfly.security.password.spec.ScramDigestPasswordSpec;

/**
 * A {@link org.wildfly.security.password.Password} implementation for {@link org.wildfly.security.password.interfaces.ScramDigestPassword}.
 *
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 */
class ScramDigestPasswordImpl extends AbstractPasswordImpl implements ScramDigestPassword {

    private static final String HMAC_SHA1_ALGORITHM = "HmacSHA1";
    private static final String HMAC_SHA256_ALGORITHM = "HmacSHA256";

    private final String algorithm;
    private final byte[] digest;
    private final byte[] salt;
    private final int iterationCount;

    ScramDigestPasswordImpl(final String algorithm, final byte[] digest, final byte[] salt, final int iterationCount) {
        this.algorithm = algorithm;
        this.digest = digest;
        this.salt = salt;
        this.iterationCount = iterationCount;
    }

    ScramDigestPasswordImpl(final ScramDigestPassword password) {
        this(password.getAlgorithm(), password.getDigest().clone(), password.getSalt().clone(), password.getIterationCount());
    }

    ScramDigestPasswordImpl(final ScramDigestPasswordSpec spec) {
        this(spec.getAlgorithm(), spec.getDigest().clone(), spec.getSalt().clone(), spec.getIterationCount());
    }

    ScramDigestPasswordImpl(final String algorithm, final ClearPasswordSpec spec) throws InvalidKeySpecException {
        this.algorithm = algorithm;
        this.salt = PasswordUtil.generateRandomSalt(DEFAULT_SALT_SIZE);
        this.iterationCount = DEFAULT_ITERATION_COUNT;
        try {
            this.digest = scramDigest(this.algorithm, getNormalizedPasswordBytes(spec.getEncodedPassword()),
                    this.salt, this.iterationCount);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new InvalidKeySpecException(e);
        }
    }

    ScramDigestPasswordImpl(final String algorithm, final EncryptablePasswordSpec spec) throws InvalidKeySpecException {
        this(algorithm, spec.getPassword(), (HashedPasswordAlgorithmSpec) spec.getAlgorithmParameterSpec());
    }

    private ScramDigestPasswordImpl(final String algorithm, final char[] password, final HashedPasswordAlgorithmSpec spec) throws InvalidKeySpecException {
        this.algorithm = algorithm;
        this.salt = spec.getSalt() == null ? PasswordUtil.generateRandomSalt(DEFAULT_SALT_SIZE) : spec.getSalt().clone();
        this.iterationCount = spec.getIterationCount() == 0 ? DEFAULT_ITERATION_COUNT : spec.getIterationCount();
        try {
            this.digest = scramDigest(algorithm, getNormalizedPasswordBytes(password), salt, iterationCount);
        } catch (Exception e) {
            throw new InvalidKeySpecException(e);
        }
    }

    @Override
    public String getAlgorithm() {
        return this.algorithm;
    }

    @Override
    public byte[] getDigest() {
        try {
            return this.digest.clone();
        } catch (NullPointerException npe) {
            throw new IllegalStateException();
        }
    }

    @Override
    public byte[] getSalt() {
        try {
            return this.salt.clone();
        } catch (NullPointerException npe) {
            throw new IllegalStateException();
        }
    }

    @Override
    public int getIterationCount() {
        return this.iterationCount;
    }

    @Override
    <T extends KeySpec> boolean convertibleTo(Class<T> keySpecType) {
        return keySpecType.isAssignableFrom(ScramDigestPasswordSpec.class);
    }

    @Override
    boolean verify(char[] guess) throws InvalidKeyException {
        try {
            byte[] output = scramDigest(this.getAlgorithm(), getNormalizedPasswordBytes(guess), this.getSalt(), this.getIterationCount());
            return Arrays.equals(this.digest, output);
        } catch (NoSuchAlgorithmException nsae) {
            throw new InvalidKeyException(nsae);
        }
    }

    @Override
    <S extends KeySpec> S getKeySpec(Class<S> keySpecType) throws InvalidKeySpecException {
        if (keySpecType.isAssignableFrom(ScramDigestPasswordSpec.class)) {
            return keySpecType.cast(new ScramDigestPasswordSpec(this.getAlgorithm(), this.getDigest(), this.getSalt(), this.getIterationCount()));
        }
        throw new InvalidKeySpecException();
    }

    /**
     * <p>
     * This method implements the SCRAM {@code Hi} function as specified by <a href="http://tools.ietf.org/html/rfc5802">
     * RFC 5802</a>. The function is defined as follows:
     *
     * <pre>
     *     Hi(str, salt, i)
     *         U1 <- HMAC(str, salt + INT(1))
     *         U2 <- HMAC(str, U1)
     *         ...
     *         Ui-1 <- HMAC(str, Ui-2)
     *         Ui <- HMAC(str, Ui-1)
     *         Hi <- U1 XOR U2 XOR ... XOR Ui
     *         return Hi
     * </pre>
     *
     * where {@code i} is the iteration count, {@code +} is the string concatenation operator, and {@code INT(g)} is a
     * 4-octet encoding of the integer {@code g}, most significant octet first.
     * </p>
     *
     * @param algorithm the algorithm that should be used to hash the password.
     * @param password the password to be hashed.
     * @param salt the salt used to hash the password.
     * @param iterationCount the iteration count used to hash the password.
     *
     * @return a byte[] containing the hashed password.
     */
    static byte[] scramDigest(final String algorithm, final byte[] password, final byte[] salt, final int iterationCount)
            throws NoSuchAlgorithmException, InvalidKeyException {

        Mac hmac = getMacInstance(algorithm, password);

        // compute U1 (see Hi function description in the javadoc).
        hmac.update(salt);
        hmac.update("\00\00\00\01".getBytes(StandardCharsets.UTF_8));
        byte[] hi = hmac.doFinal();

        // compute U2 ... Ui, performing the xor with the previous result as we iterate.
        byte[] current = hi;
        for (int i = 1; i < iterationCount; i++) {
            hmac.update(current);
            current = hmac.doFinal();
            for (int j = 0; j < hi.length; j++) {
                hi[j] ^= current[j];
            }
        }

        return hi;
    }

    /**
     * <p>
     * Builds a {@link Mac} instance using the specified algorithm and password.
     * </p>
     *
     * @param algorithm the algorithm that should be used to hash the password.
     * @param password the password to be hashed.
     * @return the constructed {@link Mac} instance.
     */
    private static Mac getMacInstance(final String algorithm, final byte[] password) throws NoSuchAlgorithmException, InvalidKeyException {
        switch (algorithm) {
            case ALGORITHM_SCRAM_SHA_1: {
                Mac hmac = Mac.getInstance(HMAC_SHA1_ALGORITHM);
                Key key = new SecretKeySpec(password, HMAC_SHA1_ALGORITHM);
                hmac.init(key);
                return hmac;
            }
            case ALGORITHM_SCRAM_SHA_256: {
                Mac hmac = Mac.getInstance(HMAC_SHA256_ALGORITHM);
                Key key = new SecretKeySpec(password, HMAC_SHA256_ALGORITHM);
                hmac.init(key);
                return hmac;
            }
            default:
                throw new NoSuchAlgorithmException("Invalid algorithm: " + algorithm);
        }
    }
}
