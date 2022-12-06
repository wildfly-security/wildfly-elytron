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

package org.wildfly.security.password.impl;

import static org.wildfly.common.math.HashMath.multiHashOrdered;
import static org.wildfly.security.password.impl.ElytronMessages.log;
import static java.lang.Math.max;
import static java.lang.Math.min;

import java.io.NotSerializableException;
import java.io.ObjectInputStream;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;

import org.wildfly.common.Assert;
import org.wildfly.security.password.spec.IteratedPasswordAlgorithmSpec;
import org.wildfly.security.password.spec.SaltedPasswordAlgorithmSpec;
import org.wildfly.security.password.interfaces.UnixSHACryptPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.password.spec.IteratedSaltedPasswordAlgorithmSpec;
import org.wildfly.security.password.spec.IteratedSaltedHashPasswordSpec;
import org.wildfly.security.password.spec.SaltedHashPasswordSpec;

/**
 * @author <a href="mailto:juraci.javadoc@kroehling.de">Juraci Paixão Kröhling</a>
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
final class UnixSHACryptPasswordImpl extends AbstractPasswordImpl implements UnixSHACryptPassword {

    private static final long serialVersionUID = 1414406780966627792L;

    private final String algorithm;
    private final byte[] salt;
    private final int iterationCount;
    private final byte[] hash;

    UnixSHACryptPasswordImpl(UnixSHACryptPassword password) {
        this(password.getAlgorithm(), truncatedClone(password.getSalt()), password.getIterationCount(), password.getHash().clone());
    }

    UnixSHACryptPasswordImpl(String algorithm, byte[] clonedSalt, int iterationCount, byte[] hash) {
        Assert.checkNotNullParam("algorithm", algorithm);
        if (!ALGORITHM_CRYPT_SHA_256.equals(algorithm) && !ALGORITHM_CRYPT_SHA_512.equals(algorithm)) {
            throw log.unrecognizedAlgorithm(algorithm);
        }

        this.salt = clonedSalt;
        this.iterationCount = iterationCount;
        this.algorithm = algorithm;
        this.hash = hash;
    }

    UnixSHACryptPasswordImpl(final String algorithm, final char[] passwordChars, final Charset hashCharset) throws NoSuchAlgorithmException {
        this(algorithm, PasswordUtil.generateRandomSalt(SALT_SIZE), DEFAULT_ITERATION_COUNT, passwordChars, hashCharset);
    }

    UnixSHACryptPasswordImpl(final String algorithm, final IteratedSaltedHashPasswordSpec spec) {
        this(algorithm, truncatedClone(spec.getSalt()), min(999_999_999, max(1_000, spec.getIterationCount())), spec.getHash().clone());
    }

    UnixSHACryptPasswordImpl(final String algorithm, final SaltedHashPasswordSpec spec) {
        this(algorithm, truncatedClone(spec.getSalt()), min(999_999_999, max(1_000, DEFAULT_ITERATION_COUNT)), spec.getHash().clone());
    }

    UnixSHACryptPasswordImpl(final String algorithm, final ClearPasswordSpec spec) throws NoSuchAlgorithmException {
        this(algorithm, spec.getEncodedPassword(), StandardCharsets.UTF_8);
    }

    UnixSHACryptPasswordImpl(final String algorithm, final IteratedSaltedPasswordAlgorithmSpec parameterSpec, final char[] password, final Charset hashCharset) throws NoSuchAlgorithmException {
        this(algorithm, truncatedClone(parameterSpec.getSalt()), min(999_999_999, max(1_000, parameterSpec.getIterationCount())), password, hashCharset);
    }

    UnixSHACryptPasswordImpl(final String algorithm, final SaltedPasswordAlgorithmSpec parameterSpec, final char[] password, final Charset hashCharset) throws NoSuchAlgorithmException {
        this(algorithm, truncatedClone(parameterSpec.getSalt()), DEFAULT_ITERATION_COUNT, password, hashCharset);
    }

    UnixSHACryptPasswordImpl(final String algorithm, final IteratedPasswordAlgorithmSpec parameterSpec, final char[] password, final Charset hashCharset) throws NoSuchAlgorithmException {
        this(algorithm, PasswordUtil.generateRandomSalt(SALT_SIZE), min(999_999_999, max(1_000, parameterSpec.getIterationCount())), password, hashCharset);
    }

    UnixSHACryptPasswordImpl(final String algorithm, final byte[] clonedSalt, final int adjustedIterationCount, final char[] password, final Charset hashCharset) throws NoSuchAlgorithmException {
        this(algorithm, clonedSalt, adjustedIterationCount, doEncode(algorithm, getNormalizedPasswordBytes(password, hashCharset), clonedSalt, adjustedIterationCount));
    }

    private static byte[] truncatedClone(final byte[] salt) {
        if (salt.length <= 16) {
            return salt.clone();
        } else {
            return Arrays.copyOf(salt, 16);
        }
    }

    @Override
    public byte[] getSalt() {
        return salt.clone();
    }

    @Override
    public int getIterationCount() {
        return iterationCount;
    }

    @Override
    public byte[] getHash() {
        return hash.clone();
    }

    @Override
    public String getAlgorithm() {
        return algorithm;
    }

    @Override
    <S extends KeySpec> S getKeySpec(Class<S> keySpecType) throws InvalidKeySpecException {
        if (keySpecType.isAssignableFrom(IteratedSaltedHashPasswordSpec.class)) {
            return keySpecType.cast(new IteratedSaltedHashPasswordSpec(this.getHash(), this.getSalt(), this.getIterationCount()));
        } else {
            throw log.invalidKeySpecExpectedSpecGotSpec(IteratedSaltedHashPasswordSpec.class.getName(), keySpecType.getName());
        }
    }

    @Override
    boolean verify(final char[] guess) throws InvalidKeyException {
        return verify(guess, StandardCharsets.UTF_8);
    }

    @Override
    boolean verify(char[] guess, Charset hashCharset) throws InvalidKeyException {
        try {
            byte[] password = getNormalizedPasswordBytes(guess, hashCharset);
            byte[] encodedGuess = doEncode(algorithm, password, salt, iterationCount);
            return MessageDigest.isEqual(getHash(), encodedGuess);
        } catch (NoSuchAlgorithmException e) {
            throw log.invalidKeyCannotVerifyPassword(e);
        }
    }

    @Override
    <T extends KeySpec> boolean convertibleTo(Class<T> keySpecType) {
        return keySpecType.isAssignableFrom(IteratedSaltedHashPasswordSpec.class);
    }

    static byte[] doEncode(final String algorithm, final byte[] password, final byte[] salt, final int iterationCount) throws NoSuchAlgorithmException {
        // see ftp://ftp.arlut.utexas.edu/pub/java_hashes/SHA-crypt.txt
        // most of the comments from this point and on are copy/paste from the url above, to make it easier
        // to correlate the code with the steps.

        // implementation note: we use "digestAC" here, because we don't need to duplicate digestA into digestAC,
        // as at the time the "digestAC" is "C", then "A" is not needed anymore.
        byte[] digestAC = getDigestA(algorithm, password, salt); // at this point, digestAC is "A"
        byte[] sequenceP = getSequenceP(algorithm, password);
        byte[] sequenceS = getSequenceS(algorithm, digestAC, salt);
        for (int i = 0 ; i < iterationCount; i++) {
            // 21. repeat a loop according to the number specified in the rounds=<N>
            // specification in the salt (or the default value if none is
            // present).  Each round is numbered, starting with 0 and up to N-1.
            //
            //     The loop uses a digest as input.  In the first round it is the
            // digest produced in step 12.  In the latter steps it is the digest
            // produced in step 21.h.  The following text uses the notation
            // "digest A/C" to describe this behavior.
            digestAC = getDigestC(algorithm, digestAC, sequenceP, sequenceS, i);
            // implementation note: at this point, digestAC is "C"
        }

        return digestAC;
    }

    /**
     * Calculates the "digest A", derived from the password and salt.
     * @param password the encoded password bytes
     * @return the digest A
     * @throws NoSuchAlgorithmException
     */
    private static byte[] getDigestA(final String algorithm, final byte[] password, final byte[] salt) throws NoSuchAlgorithmException {
        byte[] digestBResult = getDigestB(password, salt, algorithm);
        int length = password.length;

        // 1.  start digest A
        MessageDigest digestA = getMessageDigest(algorithm);

        // 2.  the password string is added to digest A
        digestA.update(password, 0, length);

        // 3.  the salt string is added to digest A.
        digestA.update(salt, 0, salt.length);

        // 9.  For each block of 32 or 64 bytes in the password string, add digest B to digest A
        int numberOfBlocksPassword = length / getInputSize(algorithm);
        for (int i = 0 ; i < numberOfBlocksPassword ; i++ ) {
            digestA.update(digestBResult, 0, getInputSize(algorithm));
        }

        // 10. For the remaining N bytes of the password string add the first N bytes of digest B to digest A
        int remainingBytesSizePassword = length % getInputSize(algorithm);
        digestA.update(digestBResult, 0, remainingBytesSizePassword);

        // 11. For each bit of the binary representation of the length of the
        // password string up to and including the highest 1-digit, starting
        // from to lowest bit position (numeric value 1):
        //
        // a) for a 1-digit add digest B to digest A
        //
        // b) for a 0-digit add the password string
        for (int i = length; i > 0 ; i >>= 1) {
            if (i % 2 != 0) {
                digestA.update(digestBResult, 0, getInputSize(algorithm));
            } else {
                digestA.update(password, 0, length);
            }
        }

        // 12. finish digest A
        return digestA.digest();
    }


    /**
     * Calculates the "sequence S", based on a given "digest A"
     *
     * @param digestA    the digest A
     * @return           the sequence S
     * @throws NoSuchAlgorithmException
     */
    private static byte[] getSequenceS(String algorithm, byte[] digestA, byte[] salt) throws NoSuchAlgorithmException {
        // 20. produce byte sequence S of the same length as the salt string where
        //
        // a) for each block of 32 or 64 bytes of length of the salt string
        // the entire digest DS is used
        //
        // b) for the remaining N (up to  31 or 63) bytes use the first N
        // bytes of digest DS
        byte[] sequenceS = new byte[salt.length];
        byte[] digestDSResult = getDigestDS(algorithm, digestA, salt);
        ByteBuffer bufferSequenceS = ByteBuffer.wrap(sequenceS);
        int numberOfBlocksSalt = salt.length / getInputSize(algorithm);
        int remainingBytesSizeSalt = salt.length % getInputSize(algorithm);

        for (int i = 0 ; i < numberOfBlocksSalt ; i++ ) {
            bufferSequenceS.put(Arrays.copyOfRange(digestDSResult, 0, getInputSize(algorithm)));
        }
        bufferSequenceS.put(Arrays.copyOfRange(digestDSResult, 0, remainingBytesSizeSalt));
        return sequenceS;
    }

    /**
     * Calculates the "digest DS", derived from the salt and on the "digest A"
     *
     * @param digestA    the digest A
     * @return           the digest DS
     * @throws NoSuchAlgorithmException
     */
    private static byte[] getDigestDS(String algorithm, byte[] digestA, byte[] salt) throws NoSuchAlgorithmException {
        // 17. start digest DS
        MessageDigest digestDS = getMessageDigest(algorithm);

        // 18. repeat the following 16+A[0] times, where A[0] represents the first
        // byte in digest A interpreted as an 8-bit unsigned value
        //
        // add the salt to digest DS
        int repeatTimes = 16 + (digestA[0] & 0xFF); // this binary-and converts the byte into "8-bit unsigned" value
        for (int i = 0 ; i < repeatTimes ; i++) {
            digestDS.update(salt, 0, salt.length);
        }

        // 19. finish digest DS
        return digestDS.digest();
    }

    /**
     * Returns the "digest B", derived from the password and salt
     *
     * @param password the encoded password bytes
     * @return the digest B
     * @throws NoSuchAlgorithmException
     */
    private static byte[] getDigestB(final byte[] password, final byte[] salt, final String algorithm) throws NoSuchAlgorithmException {
        // 4.  start digest B
        MessageDigest digestB = getMessageDigest(algorithm);

        // 5.  add the password to digest B
        digestB.update(password, 0, password.length);

        // 6.  add the salt string to digest B
        digestB.update(salt, 0, salt.length);

        // 7.  add the password again to digest B
        digestB.update(password, 0, password.length);

        // 8.  finish digest B
        return digestB.digest();
    }

    /**
     * Calculates the "digest DP", derived from the password
     *
     * @param password the encoded password bytes
     * @return the digest DP
     * @throws NoSuchAlgorithmException
     */
    private static byte[] getDigestDP(final String algorithm, final byte[] password) throws NoSuchAlgorithmException {
        // 13. start digest DP
        MessageDigest digestDP = getMessageDigest(algorithm);

        // 14. for every byte in the password add the password to digest DP
        for (byte ignored : password) {
            digestDP.update(password, 0, password.length);
        }

        // 15. finish digest DP
        return digestDP.digest();
    }

    /**
     * Calculates the "sequence P", derived from the password
     *
     * @param password the encoded password bytes
     * @return the sequence P
     * @throws NoSuchAlgorithmException
     */
    private static byte[] getSequenceP(final String algorithm, final byte[] password) throws NoSuchAlgorithmException {
        // 16. produce byte sequence P of the same length as the password where
        //
        // a) for each block of 32 or 64 bytes of length of the password string
        // the entire digest DP is used
        //
        // b) for the remaining N (up to  31 or 63) bytes use the first N
        // bytes of digest DP
        byte[] digestDPResult = getDigestDP(algorithm, password);
        byte[] sequenceP = new byte[password.length];
        ByteBuffer bufferSequenceP = ByteBuffer.wrap(sequenceP);

        int numberOfBlocksPassword = password.length / getInputSize(algorithm);
        for (int i = 0 ; i < numberOfBlocksPassword ; i++ ) {
            bufferSequenceP.put(Arrays.copyOfRange(digestDPResult, 0, getInputSize(algorithm)));
        }

        int remainingBytesSizePassword = password.length % getInputSize(algorithm);
        bufferSequenceP.put(Arrays.copyOfRange(digestDPResult, 0, remainingBytesSizePassword));

        return sequenceP;
    }


    /**
     * Calculates the "digest C", derived from the sequenceP, sequenceS, digestAC and the iteration round
     *
     * @param digestAC     the digest A/C
     * @param sequenceP    the sequence P
     * @param sequenceS    the sequence S
     * @param round        the iteration round
     * @return             the resulting digest C
     * @throws NoSuchAlgorithmException
     */
    private static byte[] getDigestC(String algorithm, byte[] digestAC, byte[] sequenceP, byte[] sequenceS, int round) throws NoSuchAlgorithmException {
        // a) start digest C
        MessageDigest digestC = getMessageDigest(algorithm);

        // b) for odd round numbers add the byte sequence P to digest C
        // c) for even round numbers add digest A/C
        if (round % 2 != 0) {
            digestC.update(sequenceP, 0, sequenceP.length);
        } else {
            digestC.update(digestAC, 0, digestAC.length);
        }

        // d) for all round numbers not divisible by 3 add the byte sequence S
        if (round % 3 != 0) {
            digestC.update(sequenceS, 0, sequenceS.length);
        }

        // e) for all round numbers not divisible by 7 add the byte sequence P
        if (round % 7 != 0) {
            digestC.update(sequenceP, 0, sequenceP.length);
        }

        // f) for odd round numbers add digest A/C
        // g) for even round numbers add the byte sequence P
        if (round % 2 != 0) {
            digestC.update(digestAC, 0, digestAC.length);
        } else {
            digestC.update(sequenceP, 0, sequenceP.length);
        }

        // h) finish digest C.
        // from the javadoc: After digest has been called, the MessageDigest object is reset to its initialized state.
        return digestC.digest();
    }

    private static MessageDigest getMessageDigest(String algorithm) throws NoSuchAlgorithmException {
        switch (algorithm) {
            case ALGORITHM_CRYPT_SHA_256: return MessageDigest.getInstance("SHA-256");
            case ALGORITHM_CRYPT_SHA_512: return MessageDigest.getInstance("SHA-512");
            default: throw log.noSuchAlgorithmInvalidAlgorithm(algorithm);
        }
    }

    private static int getInputSize(final String algorithm) throws NoSuchAlgorithmException {
        switch (algorithm) {
            case ALGORITHM_CRYPT_SHA_256: return 32;
            case ALGORITHM_CRYPT_SHA_512: return 64;
            default: throw log.noSuchAlgorithmInvalidAlgorithm(algorithm);
        }
    }

    public int hashCode() {
        return multiHashOrdered(multiHashOrdered(multiHashOrdered(Arrays.hashCode(hash), Arrays.hashCode(salt)), iterationCount), algorithm.hashCode());
    }

    public boolean equals(final Object obj) {
        if (! (obj instanceof UnixSHACryptPasswordImpl)) {
            return false;
        }
        UnixSHACryptPasswordImpl other = (UnixSHACryptPasswordImpl) obj;
        return iterationCount == other.iterationCount && algorithm.equals(other.algorithm) && Arrays.equals(hash, other.hash) && Arrays.equals(salt, other.salt);
    }

    private void readObject(ObjectInputStream ignored) throws NotSerializableException {
        throw new NotSerializableException();
    }

    Object writeReplace() {
        return UnixSHACryptPassword.createRaw(algorithm, salt, hash, iterationCount);
    }

    public UnixSHACryptPasswordImpl clone() {
        return this;
    }
}
