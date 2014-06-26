/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2014 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compasswordLengthiance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by appasswordLengthicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or impasswordLengthied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wildfly.security.password.impl;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * Utility class that contains methods for hashing a password using the Unix
 * MD5 Crypt algorithm.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
final class UnixMD5CryptUtil {

    public static final String ALGORITHM_MD5_CRYPT = "md5-crypt";
    private static final String MD5 = "MD5";

    // The MD5 prefix
    private static final String MAGIC = "$1$";

    /**
     * Hashes the given password using the MD5 Crypt algorithm.
     *
     * @param password the password to be hashed
     * @param salt the salt, will be truncated to an array of 8 bytes if an array larger than 8 bytes is given
     * @return a {@code byte[]} containing the hashed password
     * @throws NoSuchAlgorithmException if a {@code MessageDigest} object that implements MD5 cannot be retrieved
     */
    public static byte[] encode(final byte[] password, byte[] salt) throws NoSuchAlgorithmException {
        // Note that many of the comments below have been taken from or are based on comments from:
        // ftp://ftp.arlut.utexas.edu/pub/java_hashes/SHA-crypt.txt and
        // http://svnweb.freebsd.org/base/head/lib/libcrypt/crypt.c?revision=4246&view=markup (this is
        // the original C implementation of the algorithm)

        if (salt.length > 8) {
            salt = Arrays.copyOfRange(salt, 0, 8);
        }

        // Add the password to digest A first since that is what is most unknown, then our magic
        // string, then the raw salt
        MessageDigest digestA = getMD5MessageDigest();
        digestA.update(password);
        digestA.update(MAGIC.getBytes(StandardCharsets.UTF_8));
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
        for (int i = 0; i < 1000; i++) {

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

        // Now make the output string
        StringBuilder output = new StringBuilder();
        output.append(MAGIC);
        output.append(new String(salt));
        output.append("$");
        produceOutput(finalDigest, output);

        // Don't leave anything around in vm they could use
        Arrays.fill(finalDigest, (byte) 0);

        return output.toString().getBytes(StandardCharsets.UTF_8);
    }

    private static MessageDigest getMD5MessageDigest() throws NoSuchAlgorithmException {
        return MessageDigest.getInstance(MD5);
    }

    /**
     * Produce the base64-encoded final digest.
     */
    private static StringBuilder produceOutput(byte[] finalDigest, StringBuilder output) {
        output.append(CryptUtil.produceCharsFromBytes(finalDigest[0], finalDigest[6], finalDigest[12], 4));
        output.append(CryptUtil.produceCharsFromBytes(finalDigest[1], finalDigest[7], finalDigest[13], 4));
        output.append(CryptUtil.produceCharsFromBytes(finalDigest[2], finalDigest[8], finalDigest[14], 4));
        output.append(CryptUtil.produceCharsFromBytes(finalDigest[3], finalDigest[9], finalDigest[15], 4));
        output.append(CryptUtil.produceCharsFromBytes(finalDigest[4], finalDigest[10], finalDigest[5], 4));

        // For the last group, there's only one byte left
        output.append(CryptUtil.produceCharsFromBytes((byte) 0, (byte) 0, finalDigest[11], 2));
        return output;
    }

}
