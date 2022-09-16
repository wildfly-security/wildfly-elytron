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

import java.io.NotSerializableException;
import java.io.ObjectInputStream;
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
import org.wildfly.security.password.interfaces.SunUnixMD5CryptPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.password.spec.IteratedSaltedPasswordAlgorithmSpec;
import org.wildfly.security.password.spec.IteratedSaltedHashPasswordSpec;
import org.wildfly.security.password.spec.SaltedHashPasswordSpec;

/**
 * Implementation of the Sun variant of the Unix MD5 Crypt password.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
final class SunUnixMD5CryptPasswordImpl extends AbstractPasswordImpl implements SunUnixMD5CryptPassword {

    private static final long serialVersionUID = 2894797156094167807L;

    static final String MD5 = "MD5";
    static final byte[] MAGIC_BYTES = "$md5$".getBytes(StandardCharsets.UTF_8);
    static final byte[] MAGIC_BYTES_WITH_ROUNDS = "$md5,rounds=".getBytes(StandardCharsets.UTF_8);
    static final byte[] SEPARATOR_BYTES = "$".getBytes(StandardCharsets.UTF_8);
    static final int BASIC_ROUND_COUNT = 4096;

    private final String algorithm;
    private final byte[] hash;
    private final byte[] salt;
    private final int iterationCount;

    // Excerpt from Hamlet III.ii that's used by the Muffet Coin Toss algorithm
    // (the excerpt was taken from Project Gutenberg: ftp://metalab.unc.edu/pub/docs/books/gutenberg/etext98/2ws2610.txt)
    private static final String HAMLET_EXCERPT = "To be, or not to be,--that is the question:--\n"
            + "Whether 'tis nobler in the mind to suffer\n"
            + "The slings and arrows of outrageous fortune\n"
            + "Or to take arms against a sea of troubles,\n"
            + "And by opposing end them?--To die,--to sleep,--\n"
            + "No more; and by a sleep to say we end\n"
            + "The heartache, and the thousand natural shocks\n"
            + "That flesh is heir to,--'tis a consummation\n"
            + "Devoutly to be wish'd. To die,--to sleep;--\n"
            + "To sleep! perchance to dream:--ay, there's the rub;\n"
            + "For in that sleep of death what dreams may come,\n"
            + "When we have shuffled off this mortal coil,\n"
            + "Must give us pause: there's the respect\n"
            + "That makes calamity of so long life;\n"
            + "For who would bear the whips and scorns of time,\n"
            + "The oppressor's wrong, the proud man's contumely,\n"
            + "The pangs of despis'd love, the law's delay,\n"
            + "The insolence of office, and the spurns\n"
            + "That patient merit of the unworthy takes,\n"
            + "When he himself might his quietus make\n"
            + "With a bare bodkin? who would these fardels bear,\n"
            + "To grunt and sweat under a weary life,\n"
            + "But that the dread of something after death,--\n"
            + "The undiscover'd country, from whose bourn\n"
            + "No traveller returns,--puzzles the will,\n"
            + "And makes us rather bear those ills we have\n"
            + "Than fly to others that we know not of?\n"
            + "Thus conscience does make cowards of us all;\n"
            + "And thus the native hue of resolution\n"
            + "Is sicklied o'er with the pale cast of thought;\n"
            + "And enterprises of great pith and moment,\n"
            + "With this regard, their currents turn awry,\n"
            + "And lose the name of action.--Soft you now!\n"
            + "The fair Ophelia!--Nymph, in thy orisons\n"
            + "Be all my sins remember'd.\n\0"; // trailing null character is needed

    SunUnixMD5CryptPasswordImpl(final String algorithm, final byte[] clonedHash, final byte[] clonedSalt, final int iterationCount) {
        Assert.checkNotNullParam("algorithm", algorithm);
        if (!algorithm.equals(ALGORITHM_SUN_CRYPT_MD5) && !algorithm.equals(ALGORITHM_SUN_CRYPT_MD5_BARE_SALT)) {
            throw log.unrecognizedAlgorithm(algorithm);
        }

        this.algorithm = algorithm;
        this.hash = clonedHash;
        this.salt = clonedSalt;
        this.iterationCount = iterationCount;
    }

    SunUnixMD5CryptPasswordImpl(SunUnixMD5CryptPassword password) {
        this(password.getAlgorithm(), password.getHash().clone(), password.getSalt().clone(), password.getIterationCount());
    }

    SunUnixMD5CryptPasswordImpl(final String algorithm, final IteratedSaltedHashPasswordSpec spec) {
        this(algorithm, spec.getHash().clone(), spec.getSalt().clone(), spec.getIterationCount());
    }

    SunUnixMD5CryptPasswordImpl(final String algorithm, final SaltedHashPasswordSpec spec) {
        this(algorithm, spec.getHash().clone(), spec.getSalt().clone(), DEFAULT_ITERATION_COUNT);
    }

    SunUnixMD5CryptPasswordImpl(final ClearPasswordSpec spec) throws NoSuchAlgorithmException {
        this.algorithm = ALGORITHM_SUN_CRYPT_MD5;
        this.salt = PasswordUtil.generateRandomSalt(DEFAULT_SALT_SIZE);
        this.iterationCount = DEFAULT_ITERATION_COUNT;
        this.hash = sunMD5Crypt(algorithm, getNormalizedPasswordBytes(spec.getEncodedPassword()), salt, iterationCount);
    }

    SunUnixMD5CryptPasswordImpl(final String algorithm, final char[] password, final Charset hashCharset) throws NoSuchAlgorithmException {
        this(algorithm, password, PasswordUtil.generateRandomSalt(DEFAULT_SALT_SIZE), DEFAULT_ITERATION_COUNT, hashCharset);
    }

    SunUnixMD5CryptPasswordImpl(final String algorithm, final char[] password, final IteratedSaltedPasswordAlgorithmSpec spec, final Charset hashCharset) throws NoSuchAlgorithmException {
        this(algorithm, password, spec.getSalt().clone(), spec.getIterationCount(), hashCharset);
    }

    SunUnixMD5CryptPasswordImpl(final String algorithm, final char[] password, final SaltedPasswordAlgorithmSpec spec, final Charset hashCharset) throws NoSuchAlgorithmException {
        this(algorithm, password, spec.getSalt().clone(), DEFAULT_ITERATION_COUNT, hashCharset);
    }

    SunUnixMD5CryptPasswordImpl(final String algorithm, final char[] password, final IteratedPasswordAlgorithmSpec spec, final Charset hashCharset) throws NoSuchAlgorithmException {
        this(algorithm, password, PasswordUtil.generateRandomSalt(DEFAULT_SALT_SIZE), spec.getIterationCount(), hashCharset);
    }

    private SunUnixMD5CryptPasswordImpl(final String algorithm, final char[] password, final byte[] clonedSalt, final int iterationCount, final Charset hashCharset)
            throws NoSuchAlgorithmException {
        this(algorithm, sunMD5Crypt(algorithm, getNormalizedPasswordBytes(password, hashCharset), clonedSalt, iterationCount), clonedSalt, iterationCount);
    }

    @Override
    public String getAlgorithm() {
        return algorithm;
    }

    @Override
    public byte[] getHash() {
        return hash.clone();
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
    <S extends KeySpec> S getKeySpec(final Class<S> keySpecType) throws InvalidKeySpecException {
        if (keySpecType.isAssignableFrom(IteratedSaltedHashPasswordSpec.class)) {
            return keySpecType.cast(new IteratedSaltedHashPasswordSpec(getHash(), getSalt(), getIterationCount()));
        }
        throw new InvalidKeySpecException();
    }

    @Override
    boolean verify(final char[] guess) throws InvalidKeyException {
        return verify(guess, StandardCharsets.UTF_8);
    }

    @Override
    boolean verify(char[] guess, Charset hashCharset) throws InvalidKeyException {
        byte[] test;
        try {
            test = sunMD5Crypt(getAlgorithm(), getNormalizedPasswordBytes(guess, hashCharset), getSalt(), getIterationCount());
        } catch (NoSuchAlgorithmException e) {
            throw log.invalidKeyCannotVerifyPassword(e);
        }
        return MessageDigest.isEqual(getHash(), test);
    }

    @Override
    <T extends KeySpec> boolean convertibleTo(final Class<T> keySpecType) {
        return keySpecType.isAssignableFrom(IteratedSaltedHashPasswordSpec.class);
    }

    /**
     * Hashes the given password using the Sun variant of the MD5 Crypt algorithm.
     *
     * @param algorithm the algorithm to be used. Possible values are available as constants on {link}SunUnixMD5CryptPassword{link}
     * @param password the password to be hashed
     * @param salt the salt
     * @param iterationCount the number of additional iterations to use
     * @return a {@code byte[]} containing the hashed password
     * @throws NoSuchAlgorithmException if a {@code MessageDigest} object that implements MD5 cannot be retrieved
     */
    static byte[] sunMD5Crypt(final String algorithm, final byte[] password, final byte[] salt, final int iterationCount) throws NoSuchAlgorithmException {
        // Add the password to the digest first
        MessageDigest digest = getMD5MessageDigest();
        digest.update(password);

        // Now add the magic bytes, followed by the number of rounds (if specified), followed by the salt
        if (iterationCount == 0) {
            digest.update(MAGIC_BYTES);
        } else {
            digest.update(MAGIC_BYTES_WITH_ROUNDS);
            digest.update(Integer.toString(iterationCount).getBytes(StandardCharsets.UTF_8));
            digest.update(SEPARATOR_BYTES);
        }
        digest.update(salt);

        if (algorithm.equals(ALGORITHM_SUN_CRYPT_MD5)) {
            // Include the trailing "$" after the salt
            digest.update(SEPARATOR_BYTES);
        }

        byte[] result = digest.digest();

        int actualIterationCount = BASIC_ROUND_COUNT + iterationCount;
        int a, b, v, x, y;
        int[] unsignedResult = new int[16];
        for (int round = 0; round < actualIterationCount; round++) {
            digest.reset();

            // Add the previous digest
            digest.update(result, 0, 16);

            for(int i = 0; i < 16; i++) {
              unsignedResult[i] = result[i] & 0xff;
            }

            x = 0;
            y = 0;
            for (int i = 0; i < 8; i++) {
                // Build up x (an 8-bit integer)
                a = unsignedResult[i];
                b = unsignedResult[i+3];
                v = unsignedResult[(a >> (b % 5)) & 0x0f] >> ((b >> (a & 0x07)) & 0x01);
                x |= (getDigestBit(unsignedResult, v) << i);

                // Build up y (an 8-bit integer)
                a = unsignedResult[i+8];
                b = unsignedResult[(i+11) & 0x0f];
                v = unsignedResult[(a >> (b % 5)) & 0x0f] >> ((b >> (a & 0x07)) & 0x01);
                y |= (getDigestBit(unsignedResult, v) << i);
            }

            // Only the top 7 or bottom 7 bits will be used
            x = (x >> getDigestBit(unsignedResult, round)) & 0x7f;
            y = (y >> getDigestBit(unsignedResult, round + 64)) & 0x7f;

            // If the coin toss results in a 1, add a constant phrase to the digest
            int muffetCoinToss = getDigestBit(unsignedResult, x) ^ getDigestBit(unsignedResult, y);
            if (muffetCoinToss == 1) {
                digest.update(HAMLET_EXCERPT.getBytes(StandardCharsets.UTF_8));
            }

            // Add the ASCII representation of the current round to the digest
            digest.update(Integer.toString(round).getBytes(StandardCharsets.US_ASCII));
            result = digest.digest();
        }

        Arrays.fill(unsignedResult, 0);
        return result;
    }

    private static int getDigestBit(int[] unsignedResult, int bitPosition) {
        return (unsignedResult[(bitPosition >> 3) & 0x0f] >> (bitPosition & 0x07)) & 0x01;
    }

    private static MessageDigest getMD5MessageDigest() throws NoSuchAlgorithmException {
        return MessageDigest.getInstance(MD5);
    }

    public int hashCode() {
        return multiHashOrdered(multiHashOrdered(multiHashOrdered(Arrays.hashCode(hash), Arrays.hashCode(salt)), iterationCount), algorithm.hashCode());
    }

    public boolean equals(final Object obj) {
        if (! (obj instanceof SunUnixMD5CryptPasswordImpl)) {
            return false;
        }
        SunUnixMD5CryptPasswordImpl other = (SunUnixMD5CryptPasswordImpl) obj;
        return iterationCount == other.iterationCount && algorithm.equals(other.algorithm) && MessageDigest.isEqual(hash, other.hash) && Arrays.equals(salt, other.salt);
    }

    private void readObject(ObjectInputStream ignored) throws NotSerializableException {
        throw new NotSerializableException();
    }

    Object writeReplace() {
        return SunUnixMD5CryptPassword.createRaw(algorithm, salt, hash, iterationCount);
    }

    public SunUnixMD5CryptPasswordImpl clone() {
        return this;
    }

}
