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

package org.wildfly.security.password.impl;

import static org.wildfly.common.math.HashMath.multiHashOrdered;
import static org.wildfly.security._private.ElytronMessages.log;

import java.io.NotSerializableException;
import java.io.ObjectInputStream;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Locale;

import org.wildfly.common.bytes.ByteStringBuilder;
import org.wildfly.security.password.interfaces.OneTimePassword;
import org.wildfly.security.password.spec.OneTimePasswordAlgorithmSpec;
import org.wildfly.security.password.spec.OneTimePasswordSpec;

import javax.security.sasl.SaslException;

/**
 * A {@code Password} implementation for {@link OneTimePassword}.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
class OneTimePasswordImpl extends AbstractPasswordImpl implements OneTimePassword {

    private static final long serialVersionUID = 5524179164918986449L;

    private final String algorithm;
    private final byte[] hash;
    private final String seed;
    private final int sequenceNumber;

    OneTimePasswordImpl(final String algorithm, final byte[] hash, final String seed, final int sequenceNumber) {
        this.algorithm = algorithm;
        this.hash = hash;
        this.seed = seed;
        this.sequenceNumber = sequenceNumber;
    }

    OneTimePasswordImpl(final OneTimePassword password) {
        this(password.getAlgorithm(), password.getHash().clone(), password.getSeed(), password.getSequenceNumber());
    }

    OneTimePasswordImpl(final String algorithm, final OneTimePasswordSpec spec) {
        this(algorithm, spec.getHash().clone(), spec.getSeed(), spec.getSequenceNumber());
    }

    OneTimePasswordImpl(final String algorithm, final char[] password, final OneTimePasswordAlgorithmSpec spec) throws SaslException {
        this(algorithm,
                generateOTP(algorithm,
                        getNormalizedPasswordBytes(password),
                        spec.getSeed().toLowerCase(Locale.ENGLISH),
                        spec.getSequenceNumber()
                ),
                spec.getSeed(),
                spec.getSequenceNumber());
    }

    @Override
    public String getAlgorithm() {
        return this.algorithm;
    }

    @Override
    public byte[] getHash() {
        return hash.clone();
    }

    @Override
    public String getSeed() {
        return seed;
    }

    @Override
    public int getSequenceNumber() {
        return sequenceNumber;
    }

    @Override
    <S extends KeySpec> S getKeySpec(Class<S> keySpecType) throws InvalidKeySpecException {
        if (keySpecType.isAssignableFrom(OneTimePasswordSpec.class)) {
            return keySpecType.cast(new OneTimePasswordSpec(hash.clone(), seed, sequenceNumber));
        }
        throw new InvalidKeySpecException();
    }

    @Override
    boolean verify(char[] guess) throws InvalidKeyException {
        // The OTP SASL mechanism handles this (this involves updating the stored password)
        throw new InvalidKeyException();
    }

    /**
     * Generate a 64-bit OTP as specified in <a href="https://tools.ietf.org/html/rfc2289">RFC 2289</a>.
     *
     * @param algorithm the OTP algorithm, must be either "otp-md5" or "otp-sha1"
     * @param passPhrase the pass phrase, as a byte array
     * @param seed the seed
     * @param sequenceNumber the number of times the hash function will be applied
     * @return the 64-bit OTP hash
     * @throws SaslException if the given OTP algorithm is invalid
     */
    private static byte[] generateOTP(String algorithm, byte[] passPhrase, String seed, int sequenceNumber) throws SaslException {
        final MessageDigest messageDigest;
        try {
            messageDigest = getMessageDigest(algorithm);
        } catch (NoSuchAlgorithmException e) {
            throw log.mechInvalidOTPAlgorithm(algorithm).toSaslException();
        }

        // Initial step
        final ByteStringBuilder seedAndPassPhrase = new ByteStringBuilder();
        seedAndPassPhrase.append(seed);
        seedAndPassPhrase.append(passPhrase);
        byte[] hash = hashAndFold(algorithm, messageDigest, seedAndPassPhrase.toArray());

        // Computation step
        for (int i = 0; i < sequenceNumber; i++) {
            messageDigest.reset();
            hash = hashAndFold(algorithm, messageDigest, hash);
        }
        return hash;
    }

    private static MessageDigest getMessageDigest(String algorithm) throws NoSuchAlgorithmException {
        switch (algorithm) {
            case ALGORITHM_OTP_MD5:
                return MessageDigest.getInstance("MD5");
            case ALGORITHM_OTP_SHA1:
                return MessageDigest.getInstance("SHA-1");
            case ALGORITHM_OTP_SHA_256:
                return MessageDigest.getInstance("SHA-256");
            case ALGORITHM_OTP_SHA_384:
                return MessageDigest.getInstance("SHA-384");
            case ALGORITHM_OTP_SHA_512:
                return MessageDigest.getInstance("SHA-512");
            default:
                throw new NoSuchAlgorithmException();
        }
    }

    /**
     * Pass the given input through a hash function and fold the result to 64 bits.
     *
     * @param algorithm the OTP algorithm, must be either "otp-md5" or "otp-sha1"
     * @param messageDigest the {@code MessageDigest} to use when generating the hash
     * @param input the data to hash
     * @return the folded hash
     */
    private static byte[] hashAndFold(String algorithm, MessageDigest messageDigest, byte[] input) {
        messageDigest.update(input);
        byte[] result = messageDigest.digest();
        byte[] hash = new byte[OTP_HASH_SIZE];

        // Fold the result (either 128 bits for MD5 or 160 bits for SHA-1) to 64 bits
        for (int i = OTP_HASH_SIZE; i < result.length; i++) {
            result[i % OTP_HASH_SIZE] ^= result[i];
        }
        System.arraycopy(result, 0, hash, 0, OTP_HASH_SIZE);

        if (algorithm.equals(ALGORITHM_OTP_SHA1)) {
            reverse(hash, 0, 4);
            reverse(hash, 4, 4);
        }
        return hash;
    }

    private static void reverse(byte[] bytes, int offset, int length) {
        byte tmp;
        int mid = (length / 2) + offset;
        for (int i = offset, j = offset + length - 1; i < mid; i++, j--) {
            tmp = bytes[i];
            bytes[i] = bytes[j];
            bytes[j] = tmp;
        }
    }

    @Override
    <T extends KeySpec> boolean convertibleTo(Class<T> keySpecType) {
        return keySpecType.isAssignableFrom(OneTimePasswordSpec.class);
    }

    public int hashCode() {
        return multiHashOrdered(multiHashOrdered(multiHashOrdered(Arrays.hashCode(hash),seed.hashCode()), sequenceNumber), algorithm.hashCode());
    }

    public boolean equals(final Object obj) {
        if (! (obj instanceof OneTimePasswordImpl)) {
            return false;
        }
        OneTimePasswordImpl other = (OneTimePasswordImpl) obj;
        return sequenceNumber == other.sequenceNumber && algorithm.equals(other.algorithm) && Arrays.equals(hash, other.hash) && seed.equals(other.seed);
    }

    private void readObject(ObjectInputStream ignored) throws NotSerializableException {
        throw new NotSerializableException();
    }

    Object writeReplace() {
        return OneTimePassword.createRaw(algorithm, hash, seed, sequenceNumber);
    }

    public OneTimePasswordImpl clone() {
        return this;
    }

}
