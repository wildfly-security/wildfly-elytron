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

import org.wildfly.security.password.spec.SaltedPasswordAlgorithmSpec;
import org.wildfly.security.password.interfaces.UnixMD5CryptPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.password.spec.SaltedHashPasswordSpec;

/**
 * Implementation of the Unix MD5 Crypt password.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
final class UnixMD5CryptPasswordImpl extends AbstractPasswordImpl implements UnixMD5CryptPassword {

    private static final long serialVersionUID = 8315521712238708363L;

    static final String MD5 = "MD5";
    static final byte[] MAGIC_BYTES = "$1$".getBytes(StandardCharsets.UTF_8);

    private final byte[] hash;
    private final byte[] salt;

    UnixMD5CryptPasswordImpl(final byte[] clonedHash, final byte[] clonedSalt) {
        this.hash = clonedHash;
        this.salt = clonedSalt;
    }

    UnixMD5CryptPasswordImpl(UnixMD5CryptPassword password) {
        this(password.getHash().clone(), truncatedClone(password.getSalt()));
    }

    UnixMD5CryptPasswordImpl(final SaltedHashPasswordSpec spec) {
        this(spec.getHash().clone(), truncatedClone(spec.getSalt()));
    }

    UnixMD5CryptPasswordImpl(final ClearPasswordSpec spec) throws NoSuchAlgorithmException {
        this.salt = PasswordUtil.generateRandomSalt(SALT_SIZE);
        this.hash = encode(getNormalizedPasswordBytes(spec.getEncodedPassword()), this.salt);
    }

    UnixMD5CryptPasswordImpl(final char[] password, final Charset hashCharset) throws NoSuchAlgorithmException {
        this(password, PasswordUtil.generateRandomSalt(SALT_SIZE), hashCharset);
    }

    UnixMD5CryptPasswordImpl(final char[] password, final SaltedPasswordAlgorithmSpec spec, final Charset hashCharset) throws NoSuchAlgorithmException {
        this(password, truncatedClone(spec.getSalt()), hashCharset);
    }

    UnixMD5CryptPasswordImpl(final char[] password, final byte[] salt, final Charset hashCharset) throws NoSuchAlgorithmException {
        this(encode(getNormalizedPasswordBytes(password, hashCharset), salt), salt);
    }

    private static byte[] truncatedClone(final byte[] salt) {
        if (salt.length <= SALT_SIZE) {
            return salt.clone();
        } else {
            return Arrays.copyOf(salt, SALT_SIZE);
        }
    }

    @Override
    public String getAlgorithm() {
        return ALGORITHM_CRYPT_MD5;
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
    <S extends KeySpec> S getKeySpec(final Class<S> keySpecType) throws InvalidKeySpecException {
        if (keySpecType.isAssignableFrom(SaltedHashPasswordSpec.class)) {
            return keySpecType.cast(new SaltedHashPasswordSpec(getHash(), getSalt()));
        }
        throw new InvalidKeySpecException();
    }

    @Override
    boolean verify(final char[] guess) throws InvalidKeyException {
        return verify(guess, StandardCharsets.UTF_8);
    }

    @Override
    boolean verify(char[] guess, Charset hashCharset) throws InvalidKeyException {
        byte[] guessAsBytes = getNormalizedPasswordBytes(guess, hashCharset);
        byte[] test;
        try {
            test = encode(guessAsBytes, getSalt());
        } catch (NoSuchAlgorithmException e) {
            throw log.invalidKeyCannotVerifyPassword(e);
        }
        return MessageDigest.isEqual(getHash(), test);
    }

    @Override
    <T extends KeySpec> boolean convertibleTo(final Class<T> keySpecType) {
        return keySpecType.isAssignableFrom(SaltedHashPasswordSpec.class);
    }

    /**
     * Hashes the given password using the MD5 Crypt algorithm.
     *
     * @param password the password to be hashed
     * @param salt the salt, will be truncated to an array of 8 bytes if an array larger than 8 bytes is given
     * @return a {@code byte[]} containing the hashed password
     * @throws NoSuchAlgorithmException if a {@code MessageDigest} object that implements MD5 cannot be retrieved
     */
    static byte[] encode(final byte[] password, byte[] salt) throws NoSuchAlgorithmException {
        // Note that many of the comments below have been taken from or are based on comments from:
        // ftp://ftp.arlut.utexas.edu/pub/java_hashes/SHA-crypt.txt and
        // http://svnweb.freebsd.org/base/head/lib/libcrypt/crypt.c?revision=4246&view=markup (this is
        // the original C implementation of the algorithm)

        if (salt.length > SALT_SIZE) {
            salt = Arrays.copyOfRange(salt, 0, SALT_SIZE);
        }

        // Add the password to digest A first since that is what is most unknown, then our magic
        // string, then the raw salt
        MessageDigest digestA = getMD5MessageDigest();
        digestA.update(password);
        digestA.update(MAGIC_BYTES);
        digestA.update(salt);

        // Add the password to digest B, followed by the salt, followed by the password again
        MessageDigest digestB = getMD5MessageDigest();
        digestB.update(password);
        digestB.update(salt);
        digestB.update(password);

        // Finish digest B
        byte[] finalDigest = digestB.digest();

        // For each block of 16 bytes in the password string, add digest B to digest A and for the
        // remaining N bytes of the password string, add the first N bytes of digest B to digest A
        for (int i = password.length; i > 0; i -= 16) {
            digestA.update(finalDigest, 0, i > 16 ? 16 : i);
        }

        // Don't leave anything around in vm they could use
        Arrays.fill(finalDigest, (byte) 0);

        // For each bit in the binary representation of the length of the password string up to
        // and including the highest 1-digit, starting from the lowest bit position (numeric value 1):
        // a) for a 1-digit, add a null character to digest A
        // b) for a 0-digit, add the first character of the password to digest A
        for (int i = password.length; i > 0; i >>= 1) {
            if ((i & 1) == 1) {
                digestA.update(finalDigest, 0, 1);
            } else {
                digestA.update(password, 0, 1);
            }
        }

        // Finish digest A
        finalDigest = digestA.digest();

        // The algorithm uses a fixed number of iterations
        for (int i = 0; i < ITERATION_COUNT; i++) {

            // Start a new digest
            digestB = getMD5MessageDigest();

            // If the round is odd, add the password to this digest
            // Otherwise, add the previous round's digest (or digest A if this is round 0)
            if ((i & 1) == 1) {
                digestB.update(password);
            } else {
                digestB.update(finalDigest, 0, 16);
            }

            // If the round is not divisible by 3, add the salt
            if ((i % 3) != 0) {
                digestB.update(salt);
            }

            // If the round is not divisible by 7, add the password
            if ((i % 7) != 0) {
                digestB.update(password);
            }

            // If the round is odd, add the previous round's digest (or digest A if this is round 0)
            // Otherwise, add the password
            if ((i & 1) == 1) {
                digestB.update(finalDigest, 0, 16);
            } else {
                digestB.update(password);
            }

            finalDigest = digestB.digest();
        }
        return finalDigest;
    }

    static MessageDigest getMD5MessageDigest() throws NoSuchAlgorithmException {
        return MessageDigest.getInstance(MD5);
    }

    public int hashCode() {
        return multiHashOrdered(Arrays.hashCode(hash), Arrays.hashCode(salt));
    }

    public boolean equals(final Object obj) {
        if (! (obj instanceof UnixMD5CryptPasswordImpl)) {
            return false;
        }
        UnixMD5CryptPasswordImpl other = (UnixMD5CryptPasswordImpl) obj;
        return MessageDigest.isEqual(hash, other.hash) && Arrays.equals(salt, other.salt);
    }

    private void readObject(ObjectInputStream ignored) throws NotSerializableException {
        throw new NotSerializableException();
    }

    Object writeReplace() {
        return UnixMD5CryptPassword.createRaw(getAlgorithm(), salt, hash);
    }

    public UnixMD5CryptPasswordImpl clone() {
        return this;
    }

}
