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

import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.concurrent.ThreadLocalRandom;

import org.wildfly.security.password.interfaces.BSDUnixDESCryptPassword;
import org.wildfly.security.password.spec.BSDUnixDESCryptPasswordSpec;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.password.spec.EncryptablePasswordSpec;
import org.wildfly.security.password.spec.HashedPasswordAlgorithmSpec;

/**
 * Implementation of the BSD variant of the Unix DES Crypt password.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
class BSDUnixDESCryptPasswordImpl extends AbstractPasswordImpl implements BSDUnixDESCryptPassword {

    private static final long serialVersionUID = 4537505177089490619L;
    private final int iterationCount;
    private final int salt;
    private final byte[] hash;

    BSDUnixDESCryptPasswordImpl(final BSDUnixDESCryptPasswordSpec passwordSpec) throws InvalidKeySpecException {
        this.salt = passwordSpec.getSalt();
        this.iterationCount = passwordSpec.getIterationCount();
        final byte[] hash = passwordSpec.getHash();
        if (hash == null || hash.length != BSDUnixDESCryptPassword.BSD_CRYPT_DES_HASH_SIZE) {
            throw new InvalidKeySpecException("BSD DES crypt password hash must be 64 bits");
        }
        this.hash = hash.clone();
    }

    BSDUnixDESCryptPasswordImpl(final ClearPasswordSpec passwordSpec) {
        this.salt = ThreadLocalRandom.current().nextInt() & 0xffffff;
        this.iterationCount = DEFAULT_ITERATION_COUNT;
        this.hash = generateHash(salt, iterationCount, passwordSpec.getEncodedPassword());
    }

    BSDUnixDESCryptPasswordImpl(final EncryptablePasswordSpec encryptableSpec) throws InvalidParameterSpecException {
        this(encryptableSpec.getPassword(), (HashedPasswordAlgorithmSpec) encryptableSpec.getAlgorithmParameterSpec());
    }

    private BSDUnixDESCryptPasswordImpl(final char[] password, final HashedPasswordAlgorithmSpec spec) throws InvalidParameterSpecException {
        final byte[] saltBytes = spec.getSalt();
        final int saltInt;
        if (saltBytes != null) {
            if (saltBytes.length != BSDUnixDESCryptPassword.BSD_CRYPT_DES_SALT_SIZE) {
                throw new InvalidParameterSpecException("Salt must be three bytes (24 bits)");
            }
            saltInt = (saltBytes[0] & 0xff) << 16 | (saltBytes[1] & 0xff) << 8 | (saltBytes[2] & 0xff);
        } else {
            saltInt = ThreadLocalRandom.current().nextInt() & 0xffffff;
        }
        this.salt = saltInt;
        this.iterationCount = spec.getIterationCount() == 0 ? DEFAULT_ITERATION_COUNT : spec.getIterationCount();
        this.hash = generateHash(salt, iterationCount, password);
    }

    BSDUnixDESCryptPasswordImpl(final BSDUnixDESCryptPassword password) throws InvalidKeyException {
        this.salt = password.getSalt();
        this.iterationCount = password.getIterationCount();
        final byte[] hash = password.getHash();
        if (hash == null || hash.length != BSDUnixDESCryptPassword.BSD_CRYPT_DES_HASH_SIZE) {
            throw new InvalidKeyException("BSD DES crypt password hash must be 64 bits");
        }
        this.hash = hash.clone();
    }

    <S extends KeySpec> S getKeySpec(final Class<S> keySpecType) throws InvalidKeySpecException {
        if (keySpecType.isAssignableFrom(BSDUnixDESCryptPasswordSpec.class)) {
            return keySpecType.cast(new BSDUnixDESCryptPasswordSpec(hash.clone(), salt, iterationCount));
        }
        throw new InvalidKeySpecException();
    }

    boolean verify(final char[] guess) throws InvalidKeyException {
        return Arrays.equals(hash, generateHash(salt, iterationCount, guess));
    }

    <T extends KeySpec> boolean convertibleTo(final Class<T> keySpecType) {
        return keySpecType.isAssignableFrom(BSDUnixDESCryptPasswordSpec.class);
    }

    public String getAlgorithm() {
        return BSDUnixDESCryptPassword.ALGORITHM_BSD_CRYPT_DES;
    }

    @Override
    public int getIterationCount() {
        return iterationCount;
    }

    public int getSalt() {
        return salt;
    }

    public byte[] getHash() {
        return hash.clone();
    }

    private static byte[] generateHash(final int salt, int iterationCount, final char[] password) {
        final byte[] bytes1 = getNormalizedPasswordBytes(password);
        return crypt(bytes1, salt, iterationCount);
    }

    // Note that the following DES tables and some of the methods below are based on
    // tables and methods from the C implementation of the algorithm that's used by
    // FreeBSD, NetBSD, and OpenBSD:
    // http://svnweb.freebsd.org/base/head/secure/lib/libcrypt/crypt-des.c?view=markup

    private static boolean tablesInitialized = false;

    private static final byte[] IP = {
        58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17,  9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
    };
    private static final int[][] ipMaskLeft = new int[8][256];
    private static final int[][] ipMaskRight = new int[8][256];
    private static final int[][] fpMaskLeft = new int[8][256];
    private static final int[][] fpMaskRight = new int[8][256];
    private static final byte[] initPerm = new byte[64];
    private static final byte[] finalPerm = new byte[64];

    private static final byte[] keyShifts = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};

    private static final byte[] keyPerm = {
        57, 49, 41, 33, 25, 17,  9,  1, 58, 50, 42, 34, 26, 18,
        10,  2, 59, 51, 43, 35, 27, 19, 11,  3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,  7, 62, 54, 46, 38, 30, 22,
        14,  6, 61, 53, 45, 37, 29, 21, 13,  5, 28, 20, 12,  4
    };
    private static final byte[] invKeyPerm = new byte[64];
    private static final int[][] keyPermMaskLeft = new int[8][128];
    private static final int[][] keyPermMaskRight = new int[8][128];

    private static final byte[] compPerm = {
        14, 17, 11, 24,  1,  5,  3, 28, 15,  6, 21, 10,
        23, 19, 12,  4, 26,  8, 16,  7, 27, 20, 13,  2,
        41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
        44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
    };
    private static final int[] invCompPerm = new int[56];
    private static final int[][] compPermMaskLeft = new int[8][128];
    private static final int[][] compPermMaskRight = new int[8][128];

    private static final byte[][] SBox = {
        {
            14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7,
             0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8,
             4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0,
            15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13
        },
        {
            15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10,
             3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5,
             0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15,
            13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9
        },
        {
            10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8,
            13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,
            13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7,
             1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12
        },
        {
             7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15,
            13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9,
            10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4,
             3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14
        },
        {
             2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9,
            14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6,
             4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14,
            11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3
        },
        {
            12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11,
            10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8,
             9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6,
             4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13
        },
        {
             4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1,
            13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6,
             1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2,
             6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12
        },
        {
            13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7,
             1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2,
             7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8,
             2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11
        }
    };
    private static final int[][] mSBox = new int[4][4096];
    private static final byte[][] invSBox = new byte[8][64];

    private static final byte[] PBox = {
        16,  7, 20, 21, 29, 12, 28, 17,  1, 15, 23, 26,  5, 18, 31, 10,
         2,  8, 24, 14, 32, 27,  3,  9, 19, 13, 30,  6, 22, 11,  4, 25
    };
    private static final byte[] invPBox = new byte[32];

    private static final int[][] PSBox = new int[4][256];

    private static final int[] bits32 = {
        0x80000000, 0x40000000, 0x20000000, 0x10000000, 0x08000000, 0x04000000, 0x02000000, 0x01000000,
        0x00800000, 0x00400000, 0x00200000, 0x00100000, 0x00080000, 0x00040000, 0x00020000, 0x00010000,
        0x00008000, 0x00004000, 0x00002000, 0x00001000, 0x00000800, 0x00000400, 0x00000200, 0x00000100,
        0x00000080, 0x00000040, 0x00000020, 0x00000010, 0x00000008, 0x00000004, 0x00000002, 0x00000001
    };

    /**
     * Initializes the DES tables.
     */
    private static void setupTables() {
        int inBit, outBit;
        int bits28Offset = 4;
        int bits24Offset = 8;
        int bits8Offset = 24;

        // Invert the S-boxes and then convert them into 4 arrays
        int b;
        for (int i = 0; i < 8; i++) {
            for (int j = 0; j < 64; j++) {
                b = (j & 0x20) | ((j & 1) << 4) | ((j >>> 1) & 0xf);
                invSBox[i][j] = SBox[i][b];
            }
        }

        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 64; j++) {
                for (int k = 0; k < 64; k++) {
                    mSBox[i][(j << 6) | k] = ((invSBox[(i << 1)][j] << 4) | invSBox[(i << 1) + 1][k]) & 0xff;
                }
            }
        }

        // Compute the initial and final permutations and also initialize the inverted key permutation
        for (int i = 0; i < 64; i++) {
            finalPerm[i] = (byte) (IP[i] - 1);
            initPerm[finalPerm[i]] = (byte) i;
            invKeyPerm[i] = (byte) 255;
        }

        // Invert the key permutation and initialize the inverted key compression permutation
        for (int i = 0; i < 56; i++) {
            invKeyPerm[keyPerm[i] - 1] = (byte) i;
            invCompPerm[i] = 255 & 0xff;
        }

        // Invert the key compression permutation
        for (int i = 0; i < 48; i++) {
            invCompPerm[compPerm[i] - 1] = i;
        }

        // Set up mask arrays
        for (int i = 0; i < 8; i++) {
            for (int j = 0; j < 256; j++) {
                ipMaskLeft[i][j] = 0;
                ipMaskRight[i][j] = 0;
                fpMaskLeft[i][j] = 0;
                fpMaskRight[i][j] = 0;
                for (int k = 0; k < 8; k++) {
                    inBit = 8 * i + k;
                    if ((j & bits32[bits8Offset + k]) != 0) {
                        outBit = initPerm[inBit];
                        if (outBit < 32) {
                            ipMaskLeft[i][j] |= bits32[outBit];
                        } else {
                            ipMaskRight[i][j] |= bits32[outBit - 32];
                        }

                        outBit = finalPerm[inBit];
                        if (outBit < 32) {
                            fpMaskLeft[i][j] |= bits32[outBit];
                        } else {
                            fpMaskRight[i][j] |= bits32[outBit - 32];
                        }
                    }
                }
            }
            for (int j = 0; j < 128; j++) {
                keyPermMaskLeft[i][j] = 0;
                keyPermMaskRight[i][j] = 0;
                for (int k = 0; k < 7; k++) {
                    inBit = 8 * i + k;
                    if ((j & bits32[bits8Offset + k + 1]) != 0) {
                        outBit = invKeyPerm[inBit];
                        if (outBit == 255) {
                            continue;
                        } else if (outBit < 28) {
                            keyPermMaskLeft[i][j] |= bits32[bits28Offset + outBit];
                        } else {
                            keyPermMaskRight[i][j] |= bits32[bits28Offset + (outBit - 28)];
                        }
                    }
                }

                compPermMaskLeft[i][j] = 0;
                compPermMaskRight[i][j] = 0;
                for (int k = 0; k < 7; k++) {
                    inBit = 7 * i + k;
                    if ((j & bits32[bits8Offset + k + 1]) != 0) {
                        outBit = invCompPerm[inBit];
                        if (outBit == 255) {
                            continue;
                        } else if (outBit < 24) {
                            compPermMaskLeft[i][j] |= bits32[bits24Offset + outBit];
                        } else {
                            compPermMaskRight[i][j] |= bits32[bits24Offset + outBit - 24];
                        }
                    }
                }
            }
        }

        // Invert the P-box permutation
        for (int i = 0; i < 32; i++) {
            invPBox[PBox[i] - 1] = (byte) i;
        }

        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 256; j++) {
                PSBox[i][j] = 0;
                for (int k = 0; k < 8; k++) {
                    if ((j & bits32[bits8Offset + k]) != 0) {
                        PSBox[i][j] |= bits32[invPBox[8 * i + k]];
                    }
                }
            }
        }
        tablesInitialized = true;
    }

    /**
     * Hashes the given password using the BSD variant of the Unix DES Crypt algorithm.
     *
     * @param password the password to be hashed
     * @param salt the 24-bit salt to be used
     * @param iterationCount the number of iterations to use, must be between 1 and 16777215, inclusive
     * @return a {@code byte[]} containing the hashed password
     */
    static byte[] crypt(final byte[] password, final int salt, final int iterationCount) {
        byte[] hash = new byte[8];
        byte[] currentKey;
        byte[] nextGroup;
        int[] currentSchedule;

        if (iterationCount < 1 || iterationCount > 16777215) {
            throw new IllegalArgumentException("Invalid number of rounds. Must be an integer between 1 and 16777215, inclusive");
        }

        if (!tablesInitialized) {
            setupTables();
        }

        // The first group becomes the initial key
        currentKey = getKeyGroup(password, 0);

        int nextStartIndex = 8;
        int passwordLen = password.length;
        while (nextStartIndex < passwordLen) {
            currentSchedule = desSetKey(currentKey);

            // Encrypt the current key using itself as the input
            hash = desCipher(currentSchedule, fourBytesToInt(currentKey, 0), fourBytesToInt(currentKey, 4), 0, 1);

            // XOR the result with the next group to get the next key
            nextGroup = getKeyGroup(password, nextStartIndex);
            for (int i = 0; i < nextGroup.length; i++) {
                currentKey[i] = (byte)(hash[i] ^ nextGroup[i]);
            }

            nextStartIndex += 8;
        }

        currentSchedule = desSetKey(currentKey);

        // Encrypt the current key using an input of 0
        hash = desCipher(currentSchedule, 0, 0, salt, iterationCount);
        return hash;
    }

    /**
     * Gets the key group from the given password that starts at the given index. The key
     * group contains 8 bytes and is such that the byte at index i contains the lower
     * 7 bits of the byte at {@code password[startIndex + i]}.
     *
     * @param password the password
     * @param startIndex the index where the key group begins
     * @return a {@code byte[]} containing the key group
     */
    private static byte[] getKeyGroup(final byte[] password, int startIndex) {
        final byte[] keyGroup = new byte[8];
        for (int i = 0; i < keyGroup.length; i++) {
            keyGroup[i] = 0;
        }

        int index = startIndex;
        for (int i = 0; i < keyGroup.length && index < password.length; i++) {
            final int iChar = password[index++];
            keyGroup[i] = (byte) (iChar << 1);
        }
        return keyGroup;
    }

    /**
     * Calculates the key schedule for the given key. The key schedule contains
     * 16 subkeys, each of which can be represented by a pair of integers.
     *
     * @param key the key
     * @return an {@code int[]} of size 32 containing the key schedule
     */
    private static int[] desSetKey(final byte[] key) {
        final int[] schedule = new int[32];
        int key0 = fourBytesToInt(key, 0);
        int key1 = fourBytesToInt(key, 4);

        // Permute the key and split it into two 28-bit subkeys
        int k0 = keyPermMaskLeft[0][key0 >>> 25] | keyPermMaskLeft[1][(key0 >>> 17) & 0x7f]
                | keyPermMaskLeft[2][(key0 >>> 9) & 0x7f] | keyPermMaskLeft[3][(key0 >>> 1) & 0x7f]
                | keyPermMaskLeft[4][key1 >>> 25] | keyPermMaskLeft[5][(key1 >>> 17) & 0x7f]
                | keyPermMaskLeft[6][(key1 >>> 9) & 0x7f] | keyPermMaskLeft[7][(key1 >>> 1) & 0x7f];

        int k1 = keyPermMaskRight[0][key0 >>> 25] | keyPermMaskRight[1][(key0 >>> 17) & 0x7f]
                | keyPermMaskRight[2][(key0 >>> 9) & 0x7f] | keyPermMaskRight[3][(key0 >>> 1) & 0x7f]
                | keyPermMaskRight[4][key1 >>> 25] | keyPermMaskRight[5][(key1 >>> 17) & 0x7f]
                | keyPermMaskRight[6][(key1 >>> 9) & 0x7f] | keyPermMaskRight[7][(key1 >>> 1) & 0x7f];

        // Rotate the subkeys and do the compression permutation
        int shifts = 0;
        int j = 0;
        int t0, t1;
        for (int i = 0; i < 16; i++) {
            shifts += keyShifts[i];
            t0 = (k0 << shifts) | (k0 >>> (28 - shifts));
            t1 = (k1 << shifts) | (k1 >>> (28 - shifts));

            // Left half of the subkey
            schedule[j++] = compPermMaskLeft[0][(t0 >>> 21) & 0x7f] | compPermMaskLeft[1][(t0 >>> 14) & 0x7f]
                    | compPermMaskLeft[2][(t0 >>> 7) & 0x7f] | compPermMaskLeft[3][t0 & 0x7f]
                    | compPermMaskLeft[4][(t1 >>> 21) & 0x7f] | compPermMaskLeft[5][(t1 >>> 14) & 0x7f]
                    | compPermMaskLeft[6][(t1 >>> 7) & 0x7f] | compPermMaskLeft[7][t1 & 0x7f];

            // Right half of the subkey
            schedule[j++] = compPermMaskRight[0][(t0 >>> 21) & 0x7f] | compPermMaskRight[1][(t0 >>> 14) & 0x7f]
                    | compPermMaskRight[2][(t0 >>> 7) & 0x7f] | compPermMaskRight[3][t0 & 0x7f]
                    | compPermMaskRight[4][(t1 >>> 21) & 0x7f] | compPermMaskRight[5][(t1 >>> 14) & 0x7f]
                    | compPermMaskRight[6][(t1 >>> 7) & 0x7f] | compPermMaskRight[7][t1 & 0x7f];
        }
        return schedule;
    }

    /**
     * Performs DES encryption using the given key schedule, input block, salt, and iteration count.
     *
     * @param schedule the key schedule
     * @param leftInput the most significant half of the input block
     * @param rightInput the least signicant half of the input block
     * @param salt the 24-bit salt to be used
     * @param iterationCount the number of iterations to use
     * @return a {@code byte[]} containing the hashed password
     */
    private static byte[] desCipher(final int[] schedule, final int leftInput, final int rightInput, final int salt, final int iterationCount) {
        int l, r;
        int f = 0;
        final byte[] hash = new byte[8];

        int rearrangedSalt = setupSalt(salt);

        // Initial permutation
        l = ipMaskLeft[0][leftInput >>> 24] | ipMaskLeft[1][(leftInput >>> 16) & 0xff] | ipMaskLeft[2][(leftInput >>> 8) & 0xff]
                | ipMaskLeft[3][leftInput & 0xff] | ipMaskLeft[4][rightInput >>> 24] | ipMaskLeft[5][(rightInput >>> 16) & 0xff]
                | ipMaskLeft[6][(rightInput >>> 8) & 0xff] | ipMaskLeft[7][rightInput & 0xff];

        r = ipMaskRight[0][leftInput >>> 24] | ipMaskRight[1][(leftInput >>> 16) & 0xff] | ipMaskRight[2][(leftInput >>> 8) & 0xff]
                | ipMaskRight[3][leftInput & 0xff] | ipMaskRight[4][rightInput >>> 24] | ipMaskRight[5][(rightInput >>> 16) & 0xff]
                | ipMaskRight[6][(rightInput >>> 8) & 0xff] | ipMaskRight[7][rightInput & 0xff];

        int rLeft, rRight;
        int k;
        for (int i = 0; i < iterationCount; i++) {
            k = 0;
            for (int j = 0; j < 16; j++) {

                // Expand r to 48 bits (simulates the E-box)
                rLeft = ((r & 0x00000001) << 23) | ((r & 0xf8000000) >>> 9) | ((r & 0x1f800000) >>> 11)
                        | ((r & 0x01f80000) >>> 13) | ((r & 0x001f8000) >>> 15);
                rRight = ((r & 0x0001f800) << 7) | ((r & 0x00001f80) << 5) | ((r & 0x000001f8) << 3)
                        | ((r & 0x0000001f) << 1) | ((r & 0x80000000) >>> 31);

                // The salt will flip certain bits
                f = (rLeft ^ rRight) & rearrangedSalt;
                rLeft ^= (f ^ schedule[k++]);
                rRight ^= (f ^ schedule[k++]);

                // Perform S-box lookups and do the P-box permutation
                f = PSBox[0][mSBox[0][rLeft >>> 12]] | PSBox[1][mSBox[1][rLeft & 0xfff]] | PSBox[2][mSBox[2][rRight >>> 12]]
                        | PSBox[3][mSBox[3][rRight & 0xfff]];

                f ^= l;
                l = r;
                r = f;
            }

            r = l;
            l = f;
        }

        // Final permutation
        int leftOutput, rightOutput;
        leftOutput = fpMaskLeft[0][l >>> 24] | fpMaskLeft[1][(l >>> 16) & 0xff] | fpMaskLeft[2][(l >>> 8) & 0xff]
                | fpMaskLeft[3][l & 0xff] | fpMaskLeft[4][r >>> 24] | fpMaskLeft[5][(r >>> 16) & 0xff]
                | fpMaskLeft[6][(r >>> 8) & 0xff] | fpMaskLeft[7][r & 0xff];

        rightOutput = fpMaskRight[0][l >>> 24] | fpMaskRight[1][(l >>> 16) & 0xff] | fpMaskRight[2][(l >>> 8) & 0xff]
                | fpMaskRight[3][l & 0xff] | fpMaskRight[4][r >>> 24] | fpMaskRight[5][(r >>> 16) & 0xff]
                | fpMaskRight[6][(r >>> 8) & 0xff] | fpMaskRight[7][r & 0xff];

        intToFourBytes(leftOutput, hash, 0);
        intToFourBytes(rightOutput, hash, 4);
        return hash;
    }

    /**
     * Rearranges the bits in the 24-bit salt.
     */
    private static int setupSalt(int salt) {
        int resultBit = 0x800000;
        int saltBit = 1;
        int result = 0;

        for (int i = 0; i < 24; i++) {
            if ((salt & saltBit) != 0) {
                result |= resultBit;
            }
            saltBit <<= 1;
            resultBit >>= 1;
        }
        return result;
    }

    private static int fourBytesToInt(final byte[] b, int offset) {
        // Big-endian format
        final byte b4 = b[offset++];
        int value = (b4 & 0xff) << 24;
        final byte b3 = b[offset++];
        value |= (b3 & 0xff) << 16;
        final byte b2 = b[offset++];
        value |= (b2 & 0xff) << 8;
        final byte b1 = b[offset  ];
        value |= b1 & 0xff;
        return value;
    }

    private static void intToFourBytes(final int iValue, final byte[] b, int offset) {
        // Big-endian format
        b[offset++] = (byte) (iValue >>> 24 & 0xff);
        b[offset++] = (byte) (iValue >>> 16 & 0xff);
        b[offset++] = (byte) (iValue >>> 8 & 0xff);
        b[offset  ] = (byte) (iValue & 0xff);
    }
}
