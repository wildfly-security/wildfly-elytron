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

package org.wildfly.security.password;

import static java.lang.Math.max;
import static org.wildfly.security.password.interfaces.UnixSHACryptPassword.*;

import java.security.spec.InvalidKeySpecException;
import java.util.Locale;
import java.util.NoSuchElementException;

import org.wildfly.security.password.spec.BCryptPasswordSpec;
import org.wildfly.security.password.spec.BSDUnixDESCryptPasswordSpec;
import org.wildfly.security.password.spec.PasswordSpec;
import org.wildfly.security.password.spec.TrivialDigestPasswordSpec;
import org.wildfly.security.password.spec.UnixDESCryptPasswordSpec;
import org.wildfly.security.password.spec.UnixMD5CryptPasswordSpec;
import org.wildfly.security.password.spec.UnixSHACryptPasswordSpec;

/**
 * General password utilities.
 *
 * @author <a href="mailto:jpkroehling.javadoc@redhat.com">Juraci Paixão Kröhling</a>
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public class PasswordUtils {
    private PasswordUtils() {}

    // the order or value of these numbers is not important, just their uniqueness

    private static final int A_CRYPT_MD5        = 1;
    private static final int A_BCRYPT           = 2;
    private static final int A_BSD_NT_HASH      = 3;
    private static final int A_CRYPT_SHA_256    = 4;
    private static final int A_CRYPT_SHA_512    = 5;
    private static final int A_SUN_MD5_CRYPT    = 6;
    private static final int A_APACHE_HTDIGEST  = 7;
    private static final int A_BSD_CRYPT_DES    = 8;
    private static final int A_CRYPT_DES        = 9;
    private static final int A_DIGEST_MD2       = 10;
    private static final int A_DIGEST_MD5       = 11;
    private static final int A_DIGEST_SHA_1     = 12;
    private static final int A_DIGEST_SHA_256   = 13;
    private static final int A_DIGEST_SHA_384   = 14;
    private static final int A_DIGEST_SHA_512   = 15;

    private static int doIdentifyAlgorithm(char[] chars) {
        if (chars.length < 5) {
            return 0;
        }
        if (chars[0] == '$') {
            if (chars[2] == '$') {
                switch (chars[1]) {
                    case '1': return A_CRYPT_MD5;
                    case '2': return A_BCRYPT;
                    case '3': return A_BSD_NT_HASH;
                    case '5': return A_CRYPT_SHA_256;
                    case '6': return A_CRYPT_SHA_512;
                    // 'P' == phpass
                    // 'H' == phpass
                    default: return 0;
                }
            } else if (chars[3] == '$') {
                if (chars[1] == '2') {
                    if (chars[2] == 'a' || chars[2] == 'x' || chars[2] == 'y') {
                        // todo decide if we need a variation here
                        return A_BCRYPT;
                    } else {
                        return 0;
                    }
                } else {
                    return 0;
                }
            } else if (chars[4] == '$' || chars[4] == ',') {
                if (chars[1] == 'm' && chars[2] == 'd' && chars[3] == '5') {
                    return A_SUN_MD5_CRYPT;
                } else {
                    return 0;
                }
            } else if (chars[5] == '$') {
                if (chars[1] == 'a' && chars[2] == 'p' && chars[3] == 'r' && chars[4] == '1') {
                    return A_APACHE_HTDIGEST;
                } else {
                    return 0;
                }
            } else {
                return 0;
            }
        } else if (chars[0] == '_') {
            return A_BSD_CRYPT_DES;
        } else if (chars[0] == '[') {
            int idx = indexOf(chars, ']');
            if (idx != -1) {
                switch (new String(chars, 1, idx - 1).toLowerCase(Locale.US)) {
                    case "md2": return A_DIGEST_MD2;
                    case "md5": return A_DIGEST_MD5;
                    case "sha-1": return A_DIGEST_SHA_1;
                    case "sha-256": return A_DIGEST_SHA_256;
                    case "sha-384": return A_DIGEST_SHA_384;
                    case "sha-512": return A_DIGEST_SHA_512;
                    default: return 0;
                }
            } else {
                return 0;
            }
        } else if (chars.length == 13) {
            return A_CRYPT_DES;
        } else {
            return 0;
        }
    }


    /**
     * Attempt to identify the algorithm used by the given crypt string password.
     *
     * @param chars the password crypt string characters
     * @return the algorithm name, or {@code null} if no algorithm could be guessed
     */
    public static String identifyAlgorithm(char[] chars) {
        return getAlgorithmNameString(doIdentifyAlgorithm(chars));
    }

    static String getAlgorithmNameString(final int id) {
        switch (id) {
            case A_CRYPT_MD5:       return "crypt-md5";
            case A_BCRYPT:          return "bcrypt";
            case A_BSD_NT_HASH:     return "bsd-nt-hash";
            case A_CRYPT_SHA_256:   return ALGORITHM_SHA256CRYPT;
            case A_CRYPT_SHA_512:   return ALGORITHM_SHA512CRYPT;
            case A_SUN_MD5_CRYPT:   return "sun-crypt-md5";
            case A_APACHE_HTDIGEST: return "apache-htdigest";
            case A_BSD_CRYPT_DES:   return "bsd-crypt-des";
            case A_CRYPT_DES:       return "crypt-des";
            case A_DIGEST_MD2:      return "digest-md2";
            case A_DIGEST_MD5:      return "digest-md5";
            case A_DIGEST_SHA_1:    return "digest-sha-1";
            case A_DIGEST_SHA_256:  return "digest-sha-256";
            case A_DIGEST_SHA_384:  return "digest-sha-384";
            case A_DIGEST_SHA_512:  return "digest-sha-512";
            default: return null;
        }
    }

    public static String identifyAlgorithm(String string) {
        return identifyAlgorithm(string.toCharArray());
    }

    public static char[] getCryptStringChars(PasswordSpec passwordSpec) throws InvalidKeySpecException {
        StringBuilder b = getCryptStringToBuilder(passwordSpec);
        char[] chars = new char[b.length()];
        b.getChars(0, b.length(), chars, 0);
        return chars;
    }

    public static String getCryptString(PasswordSpec passwordSpec) throws InvalidKeySpecException {
        return getCryptStringToBuilder(passwordSpec).toString();
    }
    
    private static StringBuilder getCryptStringToBuilder(PasswordSpec passwordSpec) throws InvalidKeySpecException {
        if (passwordSpec == null) {
            throw new IllegalArgumentException("passwordSpec is null");
        }
        final StringBuilder b = new StringBuilder();
        if (passwordSpec instanceof BCryptPasswordSpec) {
            throw new UnsupportedOperationException("not supported yet");
        } else if (passwordSpec instanceof BSDUnixDESCryptPasswordSpec) {
            final BSDUnixDESCryptPasswordSpec spec = (BSDUnixDESCryptPasswordSpec) passwordSpec;
            final int salt = spec.getSalt();
            base64EncodeA(b, salt >> 18);
            base64EncodeA(b, salt >> 12);
            base64EncodeA(b, salt >> 6);
            base64EncodeA(b, salt);
            final int iterationCount = spec.getIterationCount();
            base64EncodeA(b, iterationCount >> 18);
            base64EncodeA(b, iterationCount >> 12);
            base64EncodeA(b, iterationCount >> 6);
            base64EncodeA(b, iterationCount);
            base64EncodeA(b, new ByteIter(spec.getHashBytes()));
        } else if (passwordSpec instanceof TrivialDigestPasswordSpec) {
            final TrivialDigestPasswordSpec spec = (TrivialDigestPasswordSpec) passwordSpec;
            final String algorithm = spec.getAlgorithm();
            b.append('[').append(algorithm).append(']');
            base64EncodeB(b, new ByteIter(spec.getDigest()));
        } else if (passwordSpec instanceof UnixDESCryptPasswordSpec) {
            final UnixDESCryptPasswordSpec spec = (UnixDESCryptPasswordSpec) passwordSpec;
            final short salt = spec.getSalt();
            base64EncodeA(b, salt >> 6);
            base64EncodeA(b, salt);
            base64EncodeA(b, new ByteIter(spec.getHashBytes()));
        } else if (passwordSpec instanceof UnixMD5CryptPasswordSpec) {
            b.append("$1$");
            final UnixMD5CryptPasswordSpec spec = (UnixMD5CryptPasswordSpec) passwordSpec;
            final byte[] salt = spec.getSalt();
            for (final byte sb : salt) {
                b.append((char) (sb & 0xff));
            }
            b.append('$');
            base64EncodeACryptLE(b, new IByteIter(spec.getHash(), MD5_IDX));
        } else if (passwordSpec instanceof UnixSHACryptPasswordSpec) {
            final UnixSHACryptPasswordSpec spec = (UnixSHACryptPasswordSpec) passwordSpec;
            final int[] interleave;
            switch (spec.getAlgorithm()) {
                case ALGORITHM_SHA256CRYPT: {
                    b.append("$5$");
                    interleave = SHA_256_IDX;
                    break;
                }
                case ALGORITHM_SHA512CRYPT: {
                    b.append("$6$");
                    interleave = SHA_512_IDX;
                    break;
                }
                default: {
                    throw new InvalidKeySpecException("Unrecognized key spec algorithm");
                }
            }
            final int iterationCount = spec.getIterationCount();
            if (iterationCount != 5_000) {
                b.append("rounds=").append(iterationCount).append('$');
            }
            final byte[] salt = spec.getSalt();
            for (final byte sb : salt) {
                b.append((char) (sb & 0xff));
            }
            b.append('$');
            base64EncodeACryptLE(b, new IByteIter(spec.getHash(), interleave));
        } else {
            throw new InvalidKeySpecException("Password spec cannot be rendered as a string");
        }
        return b;
    }

    public static PasswordSpec parseCryptString(String cryptString) throws InvalidKeySpecException {
        if (cryptString == null) {
            throw new IllegalArgumentException("cryptString is null");
        }
        return parseCryptString(cryptString.toCharArray());
    }

    public static PasswordSpec parseCryptString(char[] cryptString) throws InvalidKeySpecException {
        if (cryptString == null) {
            throw new IllegalArgumentException("cryptString is null");
        }
        final int algorithmId = doIdentifyAlgorithm(cryptString);
        switch (algorithmId) {
            case A_CRYPT_MD5: {
                return parseUnixMD5CryptPasswordString(cryptString);
            }
            case A_BCRYPT: {
                throw new UnsupportedOperationException("not supported yet");
            }
            case A_BSD_NT_HASH: {
                throw new UnsupportedOperationException("not supported yet");
            }
            case A_CRYPT_SHA_256: {
                return parseUnixSHA256CryptPasswordString(cryptString);
            }
            case A_CRYPT_SHA_512: {
                return parseUnixSHA512CryptPasswordString(cryptString);
            }
            case A_SUN_MD5_CRYPT: {
                throw new UnsupportedOperationException("not supported yet");
            }
            case A_APACHE_HTDIGEST: {
                throw new UnsupportedOperationException("not supported yet");
            }
            case A_BSD_CRYPT_DES: {
                return parseBSDUnixDESCryptPasswordString(cryptString);
            }
            case A_CRYPT_DES: {
                return parseUnixDESCryptPasswordString(cryptString);
            }
            case A_DIGEST_MD2:
            case A_DIGEST_MD5:
            case A_DIGEST_SHA_1:
            case A_DIGEST_SHA_256:
            case A_DIGEST_SHA_384:
            case A_DIGEST_SHA_512:
            {
                return parseTrivialDigestPasswordString(algorithmId, cryptString);
            }
            default: throw new InvalidKeySpecException("Unknown crypt string algorithm");
        }
    }

    static final class CharIter {
        private final char[] c;
        private int i;

        CharIter(final char[] c) {
            this.c = c;
        }

        CharIter(final char[] c, final int i) {
            this.c = c;
            this.i = i;
        }

        public boolean hasNext() {
            return i < c.length;
        }

        public int next() throws InvalidKeySpecException {
            if (! hasNext()) {
                throw new InvalidKeySpecException("Unexpected end of input string");
            }
            return c[i++];
        }

        public int current() {
            if (i == 0) throw new NoSuchElementException();
            return c[i - 1];
        }

        public int distanceTo(int ch) {
            for (int p = 0; i + p < c.length; p ++) {
                if (c[p + i] == ch) {
                    return p;
                }
            }
            return -1;
        }

        public boolean contentEquals(String other) {
            return Arrays2.equals(c, i, other);
        }

        public void skip(final int cnt) {
            i += cnt;
        }
    }

    static class ByteIter {
        private final byte[] b;
        private int i;

        ByteIter(final byte[] b) {
            this.b = b;
        }

        ByteIter(final byte[] b, final int i) {
            this.b = b;
            this.i = i;
        }

        public boolean hasNext() {
            return i < b.length;
        }

        public int next() throws InvalidKeySpecException {
            if (! hasNext()) {
                throw new InvalidKeySpecException("Unexpected end of input bytes");
            }
            return lookup(i++);
        }

        public int current() {
            if (i == 0) throw new NoSuchElementException();
            return lookup(i - 1);
        }

        protected int lookup(int idx) {
            return b[idx] & 0xff;
        }
    }

    static class IByteIter extends ByteIter {
        private final int[] interleave;

        IByteIter(final byte[] b, final int[] interleave) {
            super(b);
            this.interleave = interleave;
        }

        IByteIter(final byte[] b, final int i, final int[] interleave) {
            super(b, i);
            this.interleave = interleave;
        }

        protected int lookup(final int idx) {
            return super.lookup(interleave[idx]);
        }
    }

    private static int parseModCryptIterationCount(final CharIter iter) throws InvalidKeySpecException {
        int iterationCount;
        if (iter.contentEquals("rounds=")) {
            iter.skip(7);
            iterationCount = 0;
            for (int ch = iter.next(); ch != '$'; ch = iter.next()) {
                if (iterationCount != 999_999_999) {
                    if (ch >= '0' && ch <= '9') {
                        // multiply by 10, add next
                        iterationCount = (iterationCount << 3) + (iterationCount << 1) + ch - '0';
                        if (iterationCount > 999_999_999) {
                            // stop overflow
                            iterationCount = 999_999_999;
                        }
                    }
                } else {
                    throw new InvalidKeySpecException("Invalid character encountered");
                }
            }
        } else {
            iterationCount = 5_000;
        }
        return max(1_000, iterationCount);
    }

    private static final int[] MD5_IDX = {
        12,  6,  0,
        13,  7,  1,
        14,  8,  2,
        15,  9,  3,
         5, 10,  4,
            11
    };

    private static final int[] SHA_256_IDX = {
                20, 10,  0,
        11,  1, 21,
             2, 22, 12,
                23, 13,  3,
        14,  4, 24,
             5, 25, 15,
                26, 16,  6,
        17,  7, 27,
             8, 28, 18,
                29, 19,  9,
                30,
                31
    };

    private static final int[] SHA_512_IDX = {
            42, 21,  0,
         1, 43, 22,
                23,  2, 44,
            45, 24,  3,
         4, 46, 25,
                26,  5, 47,
            48, 27,  6,
         7, 49, 28,
                29,  8, 50,
            51, 30,  9,
        10, 52, 31,
                32, 11, 53,
            54, 33, 12,
        13, 55, 34,
                35, 14, 56,
            57, 36, 15,
        16, 58, 37,
                38, 17, 59,
            60, 39, 18,
        19, 61, 40,
                41, 20, 62,
                        63
    };

    private static TrivialDigestPasswordSpec parseTrivialDigestPasswordString(final int algorithmId, final char[] cryptString) throws InvalidKeySpecException {
        final int initialLen;
        switch (algorithmId) {
            case A_DIGEST_MD2:
            case A_DIGEST_MD5: initialLen = "[mdX]".length(); break;
            case A_DIGEST_SHA_1: initialLen = "[sha-1]".length(); break;
            case A_DIGEST_SHA_256:
            case A_DIGEST_SHA_384:
            case A_DIGEST_SHA_512: initialLen = "[sha-XXX]".length(); break;
            default: throw new IllegalStateException();
        }
        byte[] bytes = new byte[cryptString.length * 3 / 4];
        base64DecodeB(new CharIter(cryptString, initialLen), bytes);
        return new TrivialDigestPasswordSpec(getAlgorithmNameString(algorithmId), bytes);
    }

    private static UnixSHACryptPasswordSpec parseUnixSHA256CryptPasswordString(char[] cryptString) throws InvalidKeySpecException {
        assert cryptString[0] == '$'; // previously tested by doIdentifyAlgorithm
        assert cryptString[1] == '5'; // previously tested by doIdentifyAlgorithm
        assert cryptString[2] == '$'; // previously tested by doIdentifyAlgorithm
        return parseUnixSHACryptPasswordSpec(cryptString, SHA_256_IDX, ALGORITHM_SHA256CRYPT);
    }

    private static UnixSHACryptPasswordSpec parseUnixSHA512CryptPasswordString(char[] cryptString) throws InvalidKeySpecException {
        assert cryptString[0] == '$'; // previously tested by doIdentifyAlgorithm
        assert cryptString[1] == '6'; // previously tested by doIdentifyAlgorithm
        assert cryptString[2] == '$'; // previously tested by doIdentifyAlgorithm
        return parseUnixSHACryptPasswordSpec(cryptString, SHA_512_IDX, ALGORITHM_SHA512CRYPT);
    }

    private static UnixSHACryptPasswordSpec parseUnixSHACryptPasswordSpec(final char[] cryptString, final int[] table, final String algorithm) throws InvalidKeySpecException {
        CharIter i = new CharIter(cryptString, 3);
        try {
            final int iterationCount; // spec default

            // iteration count
            iterationCount = parseModCryptIterationCount(i);

            int saltByteLen = i.distanceTo('$');
            if (saltByteLen == -1) {
                throw new InvalidKeySpecException("No salt terminator given");
            }

            byte[] salt = new byte[saltByteLen];
            int b = i.next();
            int j = 0;
            while (b != '$') {
                salt[j++] = (byte) b;
                b = i.next();
            }

            byte[] hash = new byte[table.length]; // key size == table length
            base64DecodeACryptLE(i, hash, table);

            return new UnixSHACryptPasswordSpec(algorithm, hash, salt, iterationCount);
        } catch (ArrayIndexOutOfBoundsException ignored) {
            throw new InvalidKeySpecException("Unexpected end of password string");
        }
    }

    private static UnixMD5CryptPasswordSpec parseUnixMD5CryptPasswordString(final char[] cryptString) throws InvalidKeySpecException {
        assert cryptString[0] == '$'; // previously tested by doIdentifyAlgorithm
        assert cryptString[1] == '1'; // previously tested by doIdentifyAlgorithm
        assert cryptString[2] == '$'; // previously tested by doIdentifyAlgorithm
        CharIter i = new CharIter(cryptString, 3);
        try {
            int saltByteLen = i.distanceTo('$');
            if (saltByteLen == -1) {
                throw new InvalidKeySpecException("No salt terminator given");
            }

            byte[] salt = new byte[saltByteLen];
            int b = i.next();
            int j = 0;
            while (b != '$') {
                salt[j++] = (byte) b;
                b = i.next();
            }

            byte[] hash = new byte[MD5_IDX.length]; // key size == table length
            base64DecodeACryptLE(i, hash, MD5_IDX);

            return new UnixMD5CryptPasswordSpec(hash, salt);
        } catch (ArrayIndexOutOfBoundsException ignored) {
            throw new InvalidKeySpecException("Unexpected end of password string");
        }
    }

    private static UnixDESCryptPasswordSpec parseUnixDESCryptPasswordString(char[] cryptString) throws InvalidKeySpecException {
        assert cryptString.length == 13; // previously tested by doIdentifyAlgorithm
        // 12 bit salt
        short salt = (short) (base64DecodeA(cryptString[0]) << 6 | base64DecodeA(cryptString[1]));
        // 64 bit hash
        byte[] hash = new byte[8];
        base64DecodeA(new CharIter(cryptString, 2), hash);
        return new UnixDESCryptPasswordSpec(hash, salt);
    }

    private static BSDUnixDESCryptPasswordSpec parseBSDUnixDESCryptPasswordString(char[] cryptString) throws InvalidKeySpecException {
        assert cryptString.length == 20;
        assert cryptString[0] == '_';
        // 24 bit iteration count
        int iterationCount = base64DecodeA(cryptString[1]) << 18 | base64DecodeA(cryptString[2]) << 12 | base64DecodeA(cryptString[3]) << 6 | base64DecodeA(cryptString[4]);
        // 24 bit salt
        int salt = base64DecodeA(cryptString[5]) << 18 | base64DecodeA(cryptString[6]) << 12 | base64DecodeA(cryptString[7]) << 6 | base64DecodeA(cryptString[8]);
        // 64 bit hash
        byte[] hash = new byte[8];
        base64DecodeA(new CharIter(cryptString, 9), hash);
        return new BSDUnixDESCryptPasswordSpec(hash, salt, iterationCount);
    }

    /**
     * Base-64 decode a sequence of characters into an appropriately-sized byte array at the given offset with an
     * interleave table, using the modular crypt style little-endian scheme.
     *
     * @param iter the character iterator
     * @param target the target array
     * @param interleave the interleave table to use
     */
    private static void base64DecodeACryptLE(CharIter iter, byte[] target, int[] interleave) throws InvalidKeySpecException {
        int len = target.length;
        int a, b;
        for (int i = 0; i < len; ++ i) {
            a = base64DecodeA(iter.next()); // b0[5..0]
            b = base64DecodeA(iter.next()); // b1[3..0] + b0[7..6]
            target[interleave[i]] = (byte) (a | b << 6); // b0
            if (++ i >= len) break;
            a = base64DecodeA(iter.next()); // b2[1..0] + b1[7..4]
            target[interleave[i]] = (byte) (a << 4 | b >> 2); // b1
            if (++ i >= len) break;
            b = base64DecodeA(iter.next()); // b2[7..2]
            target[interleave[i]] = (byte) (b << 2 | a >> 4); // b2
        }
    }

    /**
     * Base-64 decode a sequence of characters into an appropriately-sized byte array at the given offset, using the
     * standard scheme and the modular crypt alphabet.
     *
     * @param iter the character iterator
     * @param target the target array
     */
    private static void base64DecodeA(CharIter iter, byte[] target) throws InvalidKeySpecException {
        int len = target.length;
        int a, b;
        for (int i = 0; i < len; ++ i) {
            a = base64DecodeA(iter.next());
            b = base64DecodeA(iter.next());
            target[i] = (byte) (a << 2 | b >> 4);
            if (++ i >= len) break;
            a = base64DecodeA(iter.next());
            target[i] = (byte) (b << 4 | a >> 2);
            if (++ i >= len) break;
            b = base64DecodeA(iter.next());
            target[i] = (byte) (a << 6 | b >> 0);
        }
    }

    /**
     * Base-64 decode a sequence of characters into an appropriately-sized byte array at the given offset, using the
     * standard scheme and the standard alphabet.
     *
     * @param iter the character iterator
     * @param target the target array
     */
    private static void base64DecodeB(CharIter iter, byte[] target) throws InvalidKeySpecException {
        int len = target.length;
        int a, b;
        for (int i = 0; i < len; ++ i) {
            a = base64DecodeB(iter.next());
            b = base64DecodeB(iter.next());
            target[i] = (byte) (a << 2 | b >> 4);
            if (++ i >= len) break;
            a = base64DecodeB(iter.next());
            target[i] = (byte) (b << 4 | a >> 2);
            if (++ i >= len) break;
            b = base64DecodeB(iter.next());
            target[i] = (byte) (a << 6 | b >> 0);
        }
    }

    /**
     * Base-64 decode a single character with alphabet A (DES/MD5/SHA crypt).
     *
     * @param ch the character
     * @return the byte
     * @throws InvalidKeySpecException if the character is not in the alphabet
     */
    private static int base64DecodeA(int ch) throws InvalidKeySpecException {
        if (ch == '.') {
            return 0;
        } else if (ch == '/') {
            return 1;
        } else if (ch >= '0' && ch <= '9') {
            return ch + 2 - '0';
        } else if (ch >= 'A' && ch <= 'Z') {
            return ch + 12 - 'A';
        } else if (ch >= 'a' && ch <= 'z') {
            return ch + 38 - 'a';
        } else {
            throw new InvalidKeySpecException("Invalid character encountered");
        }
    }

    /**
     * Base-64 decode a single character with alphabet B (standard Base64).
     *
     * @param ch the character
     * @return the byte
     * @throws InvalidKeySpecException if the character is not in the alphabet
     */
    private static int base64DecodeB(int ch) throws InvalidKeySpecException {
        if (ch >= 'A' && ch <= 'Z') {
            return ch - 'A';
        } else if (ch >= 'a' && ch <= 'z') {
            return ch + 26 - 'a';
        } else if (ch >= '0' && ch <= '9') {
            return ch + 52 - '0';
        } else if (ch == '+') {
            return 62;
        } else if (ch == '/') {
            return 63;
        } else {
            throw new InvalidKeySpecException("Invalid character encountered");
        }
    }

    private static void base64EncodeA(StringBuilder target, ByteIter src) throws InvalidKeySpecException {
        int a, b;
        while (src.hasNext()) {
            a = src.next();
            base64EncodeA(target, a >> 2); // top 6 bits
            if (! src.hasNext()) {
                base64EncodeA(target, a << 4); // bottom 2 bits + 0000
                return;
            }
            b = src.next();
            base64EncodeA(target, (a & 0b11) << 4 | b >> 4); // bottom 2 bits + top 4 bits
            if (! src.hasNext()) {
                base64EncodeA(target, b << 2); // bottom 4 bits + 00
                return;
            }
            a = src.next();
            base64EncodeA(target, b << 2 | a >> 6); // bottom 4 bits + top 2 bits
            base64EncodeA(target, a); // bottom 6 bits
        }
    }

    private static void base64EncodeB(StringBuilder target, ByteIter src) throws InvalidKeySpecException {
        int a, b;
        while (src.hasNext()) {
            a = src.next();
            base64EncodeB(target, a >> 2); // top 6 bits
            if (! src.hasNext()) {
                base64EncodeB(target, a << 4); // bottom 2 bits + 0000
                return;
            }
            b = src.next();
            base64EncodeB(target, (a & 0b11) << 4 | b >> 4); // bottom 2 bits + top 4 bits
            if (! src.hasNext()) {
                base64EncodeB(target, b << 2); // bottom 4 bits + 00
                return;
            }
            a = src.next();
            base64EncodeB(target, b << 2 | a >> 6); // bottom 4 bits + top 2 bits
            base64EncodeB(target, a); // bottom 6 bits
        }
    }

    private static void base64EncodeACryptLE(StringBuilder target, ByteIter src) throws InvalidKeySpecException {
        int a, b;
        while (src.hasNext()) {
            a = src.next();
            base64EncodeA(target, a); // b0[5..0]
            if (! src.hasNext()) {
                base64EncodeA(target, a >> 6); // 0000 + b0[7..6]
                return;
            }
            b = src.next();
            base64EncodeA(target, b << 2 | a >> 6); // b1[3..0] + b0[7..6]
            if (! src.hasNext()) {
                base64EncodeA(target, b >> 4); // 00 + b1[7..4]
                return;
            }
            a = src.next();
            base64EncodeA(target, a << 4 | b >> 4); // b2[1..0] + b1[7..4]
            base64EncodeA(target, a >> 2); // b2[7..2]
        }
    }

    private static void base64EncodeA(StringBuilder target, int a) {
        a &= 0b0011_1111;
        final char c;
        if (a == 0) {
            c = '.';
        } else if (a == 1) {
            c = '/';
        } else if (a < 12) {
            c = (char) (a + '0' - 2);
        } else if (a < 38) {
            c = (char) (a + 'A' - 12);
        } else { // a < 64
            c = (char) (a + 'a' - 38);
        }
        target.append(c);
    }

    private static void base64EncodeB(StringBuilder target, int a) {
        a &= 0b0011_1111;
        final char c;
        if (a < 26) {
            c = (char) (a + 'A');
        } else if (a < 52) {
            c = (char) (a + 'a' - 26);
        } else if (a < 62) {
            c = (char) (a + '0' - 52);
        } else if (a == 62) {
            c = '+';
        } else { // a == 63
            c = '/';
        }
        target.append(c);
    }

    private static int indexOf(final char[] chars, final char c) {
        for (int i = 0; i < chars.length; i ++) {
            if (chars[i] == c) return i;
        }
        return -1;
    }
}
