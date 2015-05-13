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

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;

import org.wildfly.security.password.PasswordUtil;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.interfaces.SunUnixMD5CryptPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.password.spec.EncryptablePasswordSpec;
import org.wildfly.security.password.spec.HashedPasswordAlgorithmSpec;
import org.wildfly.security.password.spec.SunUnixMD5CryptPasswordSpec;

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
        if (algorithm == null) {
            throw new IllegalArgumentException("Algorithm is null");
        }
        if (!algorithm.equals(ALGORITHM_SUN_CRYPT_MD5) && !algorithm.equals(ALGORITHM_SUN_CRYPT_MD5_BARE_SALT)) {
            throw new IllegalArgumentException("Unsupported algorithm given");
        }

        this.algorithm = algorithm;
        this.hash = clonedHash;
        this.salt = clonedSalt;
        this.iterationCount = iterationCount;
    }

    SunUnixMD5CryptPasswordImpl(SunUnixMD5CryptPassword password) {
        this(password.getAlgorithm(), password.getHash().clone(), password.getSalt().clone(), password.getIterationCount());
    }

    SunUnixMD5CryptPasswordImpl(final SunUnixMD5CryptPasswordSpec spec) {
        this(spec.getAlgorithm(), spec.getHash().clone(), spec.getSalt().clone(), spec.getIterationCount());
    }

    SunUnixMD5CryptPasswordImpl(final ClearPasswordSpec spec) throws NoSuchAlgorithmException {
        this.algorithm = ALGORITHM_SUN_CRYPT_MD5;
        this.salt = PasswordUtil.generateRandomSalt(DEFAULT_SALT_SIZE);
        this.iterationCount = DEFAULT_ITERATION_COUNT;
        this.hash = sunMD5Crypt(algorithm, getNormalizedPasswordBytes(spec.getEncodedPassword()), salt, iterationCount);
    }

    SunUnixMD5CryptPasswordImpl(final String algorithm, final EncryptablePasswordSpec spec) throws NoSuchAlgorithmException {
        this(algorithm, spec.getPassword(), (HashedPasswordAlgorithmSpec) spec.getAlgorithmParameterSpec());
    }

    private SunUnixMD5CryptPasswordImpl(final String algorithm, final char[] password, final HashedPasswordAlgorithmSpec spec) throws NoSuchAlgorithmException {
        this(algorithm, password, spec.getSalt() == null ? PasswordUtil.generateRandomSalt(DEFAULT_SALT_SIZE) : spec.getSalt().clone(), spec.getIterationCount());
    }

    private SunUnixMD5CryptPasswordImpl(final String algorithm, final char[] password, final byte[] clonedSalt, final int iterationCount)
            throws NoSuchAlgorithmException {
        this(algorithm, sunMD5Crypt(algorithm, getNormalizedPasswordBytes(password), clonedSalt, iterationCount), clonedSalt, iterationCount);
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
        if (keySpecType.isAssignableFrom(SunUnixMD5CryptPasswordSpec.class)) {
            return keySpecType.cast(new SunUnixMD5CryptPasswordSpec(getAlgorithm(), getHash(), getSalt(), getIterationCount()));
        }
        throw new InvalidKeySpecException();
    }

    @Override
    boolean canVerify(Class<?> credentialType) {
        return credentialType.isAssignableFrom(ClearPassword.class)
                || credentialType.isAssignableFrom(SunUnixMD5CryptPassword.class);
    }

    @Override
    boolean verifyCredential(Object credential) throws InvalidKeyException {
        if (credential instanceof ClearPassword) {
            char[] guess = ((ClearPassword) credential).getPassword();

            byte[] test;
            try {
                test = sunMD5Crypt(getAlgorithm(), getNormalizedPasswordBytes(guess), getSalt(), getIterationCount());
            } catch (NoSuchAlgorithmException e) {
                throw new InvalidKeyException("Cannot verify password", e);
            }
            return Arrays.equals(getHash(), test);
        } else if (credential instanceof SunUnixMD5CryptPassword) {
            SunUnixMD5CryptPassword guess = (SunUnixMD5CryptPassword) credential;

            return algorithm.equals(guess.getAlgorithm()) && iterationCount == guess.getIterationCount()
                    && Arrays.equals(salt, guess.getSalt()) && Arrays.equals(hash, guess.getHash());
        }

        return false;
    }

    @Override
    <T extends KeySpec> boolean convertibleTo(final Class<T> keySpecType) {
        return keySpecType.isAssignableFrom(SunUnixMD5CryptPasswordSpec.class);
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
}
