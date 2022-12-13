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

import static org.wildfly.common.math.HashMath.multiHashOrdered;
import static org.wildfly.security.password.impl.ElytronMessages.log;

import java.io.NotSerializableException;
import java.io.ObjectInputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.wildfly.security.password.Password;
import org.wildfly.security.password.spec.IteratedPasswordAlgorithmSpec;
import org.wildfly.security.password.spec.SaltedPasswordAlgorithmSpec;
import org.wildfly.security.password.interfaces.ScramDigestPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.password.spec.IteratedSaltedPasswordAlgorithmSpec;
import org.wildfly.security.password.spec.IteratedSaltedHashPasswordSpec;
import org.wildfly.security.password.spec.SaltedHashPasswordSpec;

/**
 * A {@link org.wildfly.security.password.Password} implementation for {@link org.wildfly.security.password.interfaces.ScramDigestPassword}.
 *
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 */
class ScramDigestPasswordImpl extends AbstractPasswordImpl implements ScramDigestPassword {

    private static final long serialVersionUID = 5831469808883867480L;

    private static final String HMAC_SHA1_ALGORITHM = "HmacSHA1";
    private static final String HMAC_SHA256_ALGORITHM = "HmacSHA256";
    private static final String HMAC_SHA384_ALGORITHM = "HmacSHA384";
    private static final String HMAC_SHA512_ALGORITHM = "HmacSHA512";

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

    ScramDigestPasswordImpl(final String algorithm, final IteratedSaltedHashPasswordSpec spec) {
        this(algorithm, spec.getHash().clone(), spec.getSalt().clone(), spec.getIterationCount());
    }

    ScramDigestPasswordImpl(final String algorithm, final SaltedHashPasswordSpec spec) {
        this(algorithm, spec.getHash().clone(), spec.getSalt().clone(), DEFAULT_ITERATION_COUNT);
    }

    ScramDigestPasswordImpl(final String algorithm, final ClearPasswordSpec spec) throws InvalidKeySpecException, NoSuchAlgorithmException, InvalidKeyException {
        this(algorithm, spec.getEncodedPassword(), PasswordUtil.generateRandomSalt(DEFAULT_SALT_SIZE), DEFAULT_ITERATION_COUNT);
    }

    ScramDigestPasswordImpl(final String algorithm, final char[] password, final Charset hashCharset) throws InvalidKeySpecException, NoSuchAlgorithmException, InvalidKeyException {
        this(algorithm, password, PasswordUtil.generateRandomSalt(DEFAULT_SALT_SIZE), DEFAULT_ITERATION_COUNT, hashCharset);
    }

    ScramDigestPasswordImpl(final String algorithm, final char[] password, final IteratedSaltedPasswordAlgorithmSpec spec, final Charset hashCharset) throws InvalidKeySpecException, NoSuchAlgorithmException, InvalidKeyException {
        this(algorithm, password, spec.getSalt(), spec.getIterationCount(), hashCharset);
    }

    ScramDigestPasswordImpl(final String algorithm, final char[] password, final SaltedPasswordAlgorithmSpec spec, final Charset hashCharset) throws InvalidKeySpecException, NoSuchAlgorithmException, InvalidKeyException {
        this(algorithm, password, spec.getSalt(), DEFAULT_ITERATION_COUNT, hashCharset);
    }

    ScramDigestPasswordImpl(final String algorithm, final char[] password, final IteratedPasswordAlgorithmSpec spec, final Charset hashCharset) throws InvalidKeySpecException, NoSuchAlgorithmException, InvalidKeyException {
        this(algorithm, password, PasswordUtil.generateRandomSalt(DEFAULT_SALT_SIZE), spec.getIterationCount(), hashCharset);
    }

    ScramDigestPasswordImpl(final String algorithm, final char[] password, final byte[] salt, final int iterationCount) throws InvalidKeyException, NoSuchAlgorithmException {
        this(algorithm, scramDigest(algorithm, getNormalizedPasswordBytes(password), salt, iterationCount), salt, iterationCount);
    }

    ScramDigestPasswordImpl(final String algorithm, final char[] password, final byte[] salt, final int iterationCount, final Charset hashCharset) throws InvalidKeyException, NoSuchAlgorithmException {
        this.algorithm = algorithm;
        this.digest = scramDigest(algorithm, getNormalizedPasswordBytes(password, hashCharset), salt, iterationCount, hashCharset);
        this.salt = salt;
        this.iterationCount = iterationCount;
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
        return keySpecType.isAssignableFrom(IteratedSaltedHashPasswordSpec.class);
    }

    @Override
    Password translate(final AlgorithmParameterSpec parameterSpec) throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (parameterSpec instanceof IteratedSaltedPasswordAlgorithmSpec) {
            IteratedSaltedPasswordAlgorithmSpec updateSpec = (IteratedSaltedPasswordAlgorithmSpec) parameterSpec;
            byte[] updateSalt = updateSpec.getSalt();
            if (updateSalt != null && ! Arrays.equals(updateSalt, salt)) {
                throw new InvalidAlgorithmParameterException();
            }
            int updateIterationCount = updateSpec.getIterationCount();
            if (updateIterationCount < this.iterationCount) {
                throw new InvalidAlgorithmParameterException();
            }
            if (updateIterationCount == this.iterationCount) {
                return this;
            }
            byte[] digest = this.digest.clone();
            try {
                addIterations(digest, getMacInstance(algorithm, digest), this.iterationCount, updateIterationCount);
            } catch (NoSuchAlgorithmException | InvalidKeyException e) {
                throw new InvalidKeyException(e);
            }
            return new ScramDigestPasswordImpl(algorithm, digest, updateSalt, updateIterationCount);
        } else if (parameterSpec instanceof IteratedPasswordAlgorithmSpec) {
            final IteratedPasswordAlgorithmSpec updateSpec = (IteratedPasswordAlgorithmSpec) parameterSpec;
            int updateIterationCount = updateSpec.getIterationCount();
            if (updateIterationCount < this.iterationCount) {
                throw new InvalidAlgorithmParameterException();
            }
            if (updateIterationCount == this.iterationCount) {
                return this;
            }
            try {
                addIterations(digest, getMacInstance(algorithm, digest), this.iterationCount, updateIterationCount);
            } catch (NoSuchAlgorithmException | InvalidKeyException e) {
                throw new InvalidKeyException(e);
            }
            return new ScramDigestPasswordImpl(algorithm, digest, salt, updateIterationCount);
        } else if (parameterSpec instanceof SaltedPasswordAlgorithmSpec) {
            SaltedPasswordAlgorithmSpec updateSpec = (SaltedPasswordAlgorithmSpec) parameterSpec;
            byte[] updateSalt = updateSpec.getSalt();
            if (updateSalt != null && ! Arrays.equals(updateSalt, salt)) {
                throw new InvalidAlgorithmParameterException();
            }
            return this;
        }
        throw new InvalidAlgorithmParameterException();
    }

    @Override
    boolean verify(char[] guess) throws InvalidKeyException {
        return verify(guess, StandardCharsets.UTF_8);
    }

    @Override
    boolean verify(char[] guess, Charset hashCharset) throws InvalidKeyException {
        if (guess.length == 0) return false;
        try {
            byte[] output = scramDigest(this.getAlgorithm(), getNormalizedPasswordBytes(guess, hashCharset), this.getSalt(), this.getIterationCount());
            return MessageDigest.isEqual(this.digest, output);
        } catch (NoSuchAlgorithmException nsae) {
            throw new InvalidKeyException(nsae);
        }
    }

    @Override
    <S extends KeySpec> S getKeySpec(Class<S> keySpecType) throws InvalidKeySpecException {
        if (keySpecType.isAssignableFrom(IteratedSaltedHashPasswordSpec.class)) {
            return keySpecType.cast(new IteratedSaltedHashPasswordSpec(this.getDigest(), this.getSalt(), this.getIterationCount()));
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
     *         U1 &lt;- HMAC(str, salt + INT(1))
     *         U2 &lt;- HMAC(str, U1)
     *         ...
     *         Ui-1 &lt;- HMAC(str, Ui-2)
     *         Ui &lt;- HMAC(str, Ui-1)
     *         Hi &lt;- U1 XOR U2 XOR ... XOR Ui
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

        return scramDigest(algorithm, password, salt, iterationCount, StandardCharsets.UTF_8);
    }

    static byte[] scramDigest(final String algorithm, final byte[] password, final byte[] salt, final int iterationCount, final Charset hashCharset)
            throws NoSuchAlgorithmException, InvalidKeyException {

        Mac hmac = getMacInstance(algorithm, password);

        // compute U1 (see Hi function description in the javadoc).
        hmac.update(salt);
        hmac.update("\00\00\00\01".getBytes(hashCharset));
        byte[] hi = hmac.doFinal();
        addIterations(hi, hmac, 1, iterationCount);
        return hi;
    }

    static void addIterations(final byte[] hi, final Mac hmac, final int currentIterationCount, final int newIterationCount) {
        // compute U2 ... Ui, performing the xor with the previous result as we iterate.
        byte[] current = hi;
        for (int i = currentIterationCount; i < newIterationCount; i++) {
            hmac.update(current);
            current = hmac.doFinal();
            for (int j = 0; j < hi.length; j++) {
                hi[j] ^= current[j];
            }
        }
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
            case ALGORITHM_SCRAM_SHA_384: {
                Mac hmac = Mac.getInstance(HMAC_SHA384_ALGORITHM);
                Key key = new SecretKeySpec(password, HMAC_SHA384_ALGORITHM);
                hmac.init(key);
                return hmac;
            }
            case ALGORITHM_SCRAM_SHA_512: {
                Mac hmac = Mac.getInstance(HMAC_SHA512_ALGORITHM);
                Key key = new SecretKeySpec(password, HMAC_SHA512_ALGORITHM);
                hmac.init(key);
                return hmac;
            }
            default:
                throw log.noSuchAlgorithmInvalidAlgorithm(algorithm);
        }
    }

    public int hashCode() {
        return multiHashOrdered(multiHashOrdered(multiHashOrdered(Arrays.hashCode(digest), Arrays.hashCode(salt)), iterationCount), algorithm.hashCode());
    }

    public boolean equals(final Object obj) {
        if (! (obj instanceof ScramDigestPasswordImpl)) {
            return false;
        }
        ScramDigestPasswordImpl other = (ScramDigestPasswordImpl) obj;
        return iterationCount == other.iterationCount && algorithm.equals(other.algorithm) && MessageDigest.isEqual(digest, other.digest) && Arrays.equals(salt, other.salt);
    }

    private void readObject(ObjectInputStream ignored) throws NotSerializableException {
        throw new NotSerializableException();
    }

    Object writeReplace() {
        return ScramDigestPassword.createRaw(algorithm, digest, salt, iterationCount);
    }

    public ScramDigestPasswordImpl clone() {
        return this;
    }

}
