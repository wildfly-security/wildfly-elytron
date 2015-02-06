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
import static org.wildfly.security.password.interfaces.SunUnixMD5CryptPassword.*;
import static org.wildfly.security.password.interfaces.UnixSHACryptPassword.*;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.spec.InvalidKeySpecException;
import java.util.Locale;
import java.util.NoSuchElementException;
import java.util.concurrent.ThreadLocalRandom;

import org.wildfly.security.password.spec.BCryptPasswordSpec;
import org.wildfly.security.password.spec.BSDUnixDESCryptPasswordSpec;
import org.wildfly.security.password.spec.PasswordSpec;
import org.wildfly.security.password.spec.SunUnixMD5CryptPasswordSpec;
import org.wildfly.security.password.spec.SimpleDigestPasswordSpec;
import org.wildfly.security.password.spec.UnixDESCryptPasswordSpec;
import org.wildfly.security.password.spec.UnixMD5CryptPasswordSpec;
import org.wildfly.security.password.spec.UnixSHACryptPasswordSpec;
import org.wildfly.security.util.Alphabet;
import org.wildfly.security.util.ByteIterator;
import org.wildfly.security.util.CodePointIterator;

/**
 * Helper utility methods for operations on passwords.
 *
 * @author <a href="mailto:jpkroehling.javadoc@redhat.com">Juraci Paixão Kröhling</a>
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class PasswordUtil {
    private PasswordUtil() {}

    // the order or value of these numbers is not important, just their uniqueness

    private static final int A_CRYPT_MD5                = 1;
    private static final int A_BCRYPT                   = 2;
    private static final int A_BSD_NT_HASH              = 3;
    private static final int A_CRYPT_SHA_256            = 4;
    private static final int A_CRYPT_SHA_512            = 5;
    private static final int A_SUN_CRYPT_MD5            = 6;
    private static final int A_APACHE_HTDIGEST          = 7;
    private static final int A_BSD_CRYPT_DES            = 8;
    private static final int A_CRYPT_DES                = 9;
    private static final int A_DIGEST_MD2               = 10;
    private static final int A_DIGEST_MD5               = 11;
    private static final int A_DIGEST_SHA_1             = 12;
    private static final int A_DIGEST_SHA_256           = 13;
    private static final int A_DIGEST_SHA_384           = 14;
    private static final int A_DIGEST_SHA_512           = 15;
    private static final int A_SUN_CRYPT_MD5_BARE_SALT  = 16;

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
                    int idx = lastIndexOf(chars, '$');
                    if (idx > 0) {
                        if (chars[idx - 1] == '$') {
                            return A_SUN_CRYPT_MD5;
                        } else {
                            return A_SUN_CRYPT_MD5_BARE_SALT;
                        }
                    } else {
                        return 0;
                    }
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
            case A_CRYPT_MD5:               return "crypt-md5";
            case A_BCRYPT:                  return "bcrypt";
            case A_BSD_NT_HASH:             return "bsd-nt-hash";
            case A_CRYPT_SHA_256:           return ALGORITHM_CRYPT_SHA_256;
            case A_CRYPT_SHA_512:           return ALGORITHM_CRYPT_SHA_512;
            case A_SUN_CRYPT_MD5:           return ALGORITHM_SUN_CRYPT_MD5;
            case A_APACHE_HTDIGEST:         return "apache-htdigest";
            case A_BSD_CRYPT_DES:           return "bsd-crypt-des";
            case A_CRYPT_DES:               return "crypt-des";
            case A_DIGEST_MD2:              return "digest-md2";
            case A_DIGEST_MD5:              return "digest-md5";
            case A_DIGEST_SHA_1:            return "digest-sha-1";
            case A_DIGEST_SHA_256:          return "digest-sha-256";
            case A_DIGEST_SHA_384:          return "digest-sha-384";
            case A_DIGEST_SHA_512:          return "digest-sha-512";
            case A_SUN_CRYPT_MD5_BARE_SALT: return ALGORITHM_SUN_CRYPT_MD5_BARE_SALT;
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
            BCryptPasswordSpec spec = (BCryptPasswordSpec) passwordSpec;
            b.append("$2a$");
            if (spec.getIterationCount() < 10)
                b.append(0);
            b.append(spec.getIterationCount());
            b.append("$");
            ByteIterator.ofBytes(spec.getSalt()).base64Encode(Alphabet.BCRYPT, false).drainTo(b);
            ByteIterator.ofBytes(spec.getHashBytes()).base64Encode(Alphabet.BCRYPT, false).drainTo(b);
        } else if (passwordSpec instanceof BSDUnixDESCryptPasswordSpec) {
            b.append('_');
            final BSDUnixDESCryptPasswordSpec spec = (BSDUnixDESCryptPasswordSpec) passwordSpec;
            final int iterationCount = spec.getIterationCount();
            b.appendCodePoint(Alphabet.MOD_CRYPT.encode(iterationCount & 0x3f));
            b.appendCodePoint(Alphabet.MOD_CRYPT.encode((iterationCount >> 6) & 0x3f));
            b.appendCodePoint(Alphabet.MOD_CRYPT.encode((iterationCount >> 12) & 0x3f));
            b.appendCodePoint(Alphabet.MOD_CRYPT.encode((iterationCount >> 18) & 0x3f));
            final int salt = spec.getSalt();
            b.appendCodePoint(Alphabet.MOD_CRYPT.encode(salt & 0x3f));
            b.appendCodePoint(Alphabet.MOD_CRYPT.encode((salt >> 6) & 0x3f));
            b.appendCodePoint(Alphabet.MOD_CRYPT.encode((salt >> 12) & 0x3f));
            b.appendCodePoint(Alphabet.MOD_CRYPT.encode((salt >> 18) & 0x3f));
            ByteIterator.ofBytes(spec.getHash()).base64Encode(Alphabet.MOD_CRYPT, false).drainTo(b);
        } else if (passwordSpec instanceof SimpleDigestPasswordSpec) {
            final SimpleDigestPasswordSpec spec = (SimpleDigestPasswordSpec) passwordSpec;
            final String algorithm = spec.getAlgorithm();
            b.append('[').append(algorithm).append(']');
            ByteIterator.ofBytes(spec.getDigest()).base64Encode().drainTo(b);
        } else if (passwordSpec instanceof UnixDESCryptPasswordSpec) {
            final UnixDESCryptPasswordSpec spec = (UnixDESCryptPasswordSpec) passwordSpec;
            final short salt = spec.getSalt();
            b.appendCodePoint(Alphabet.MOD_CRYPT.encode(salt & 0x3f));
            b.appendCodePoint(Alphabet.MOD_CRYPT.encode((salt >> 6) & 0x3f));
            ByteIterator.ofBytes(spec.getHash()).base64Encode(Alphabet.MOD_CRYPT, false).drainTo(b);
        } else if (passwordSpec instanceof UnixMD5CryptPasswordSpec) {
            b.append("$1$");
            final UnixMD5CryptPasswordSpec spec = (UnixMD5CryptPasswordSpec) passwordSpec;
            final byte[] salt = spec.getSalt();
            for (final byte sb : salt) {
                b.append((char) (sb & 0xff));
            }
            b.append('$');
            ByteIterator.ofBytes(spec.getHash(), MD5_IDX).base64Encode(Alphabet.MOD_CRYPT_LE, false).drainTo(b);
        } else if (passwordSpec instanceof SunUnixMD5CryptPasswordSpec) {
            final SunUnixMD5CryptPasswordSpec spec = (SunUnixMD5CryptPasswordSpec) passwordSpec;
            final int iterationCount = spec.getIterationCount();
            if (iterationCount > 0) {
                b.append("$md5,rounds=").append(iterationCount).append('$');
            } else {
                b.append("$md5$");
            }
            final byte[] salt = spec.getSalt();
            for (final byte sb : salt) {
                b.append((char) (sb & 0xff));
            }
            switch (spec.getAlgorithm()) {
                case ALGORITHM_SUN_CRYPT_MD5: {
                    b.append("$$");
                    break;
                }
                case ALGORITHM_SUN_CRYPT_MD5_BARE_SALT: {
                    b.append("$");
                    break;
                }
                default: {
                    throw new InvalidKeySpecException("Unrecognized key spec algorithm");
                }
            }
            ByteIterator.ofBytes(spec.getHash(), MD5_IDX).base64Encode(Alphabet.MOD_CRYPT_LE, false).drainTo(b);
        } else if (passwordSpec instanceof UnixSHACryptPasswordSpec) {
            final UnixSHACryptPasswordSpec spec = (UnixSHACryptPasswordSpec) passwordSpec;
            final int[] interleave;
            switch (spec.getAlgorithm()) {
                case ALGORITHM_CRYPT_SHA_256: {
                    b.append("$5$");
                    interleave = SHA_256_IDX;
                    break;
                }
                case ALGORITHM_CRYPT_SHA_512: {
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
            ByteIterator.ofBytes(spec.getHash(), interleave).base64Encode(Alphabet.MOD_CRYPT_LE, false).drainTo(b);
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
                return parseBCryptPasswordString(cryptString);
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
            case A_SUN_CRYPT_MD5: {
                return parseSunUnixMD5CryptPasswordString(ALGORITHM_SUN_CRYPT_MD5, cryptString);
            }
            case A_SUN_CRYPT_MD5_BARE_SALT: {
                return parseSunUnixMD5CryptPasswordString(ALGORITHM_SUN_CRYPT_MD5_BARE_SALT, cryptString);
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
                return parseSimpleDigestPasswordString(algorithmId, cryptString);
            }
            default: throw new InvalidKeySpecException("Unknown crypt string algorithm");
        }
    }

    static class IByteArrayInputStream extends ByteArrayInputStream {
        private final int[] interleave;

        IByteArrayInputStream(final byte[] buf, final int[] interleave) {
            super(buf);
            this.interleave = interleave;
        }

        IByteArrayInputStream(final byte[] buf, final int offset, final int length, final int[] interleave) {
            super(buf, offset, length);
            this.interleave = interleave;
        }

        @Override
        public synchronized int read() {
            return (pos < count) ? (buf[interleave[pos++]] & 0xff) : -1;
        }
    }

    private static int parseModCryptIterationCount(final CodePointIterator reader, final int minIterations, final int maxIterations,
            final int defaultIterations) throws InvalidKeySpecException {
        int iterationCount;
        final CodePointIterator dr = reader.delimitedBy('$');
        try {
            if (dr.limitedTo(7).contentEquals(CodePointIterator.ofString("rounds="))) {
                iterationCount = 0;
                int ch;
                while (dr.hasNext()) {
                    ch = dr.next();
                    if (iterationCount != maxIterations) {
                        if (ch >= '0' && ch <= '9') {
                            // multiply by 10, add next
                            iterationCount = (iterationCount << 3) + (iterationCount << 1) + ch - '0';
                            if (iterationCount > maxIterations) {
                                // stop overflow
                                iterationCount = maxIterations;
                            }
                        }
                    } else {
                        throw new InvalidKeySpecException("Invalid character encountered");
                    }
                }
                if (! reader.hasNext()) {
                    throw new InvalidKeySpecException("No iteration count terminator given");
                }
                reader.next(); // skip $
            } else {
                iterationCount = defaultIterations;
            }
        } catch (NoSuchElementException ignored) {
            throw new InvalidKeySpecException("Unexpected end of input string");
        }
        return max(minIterations, iterationCount);
    }

    private static int[] inverse(int[] orig) {
        final int[] n = new int[orig.length];
        for (int i = 0; i < orig.length; i ++) {
            n[orig[i]] = i;
        }
        return n;
    }

    private static final int[] MD5_IDX = {
        12,  6,  0,
        13,  7,  1,
        14,  8,  2,
        15,  9,  3,
         5, 10,  4,
            11
    };

    private static final int[] MD5_IDX_REV = inverse(MD5_IDX);

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

    private static final int[] SHA_256_IDX_REV = inverse(SHA_256_IDX);

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

    private static final int[] SHA_512_IDX_REV = inverse(SHA_512_IDX);

    private static SimpleDigestPasswordSpec parseSimpleDigestPasswordString(final int algorithmId, final char[] cryptString) throws InvalidKeySpecException {
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
        byte[] bytes = CodePointIterator.ofChars(cryptString, 0, initialLen).base64Decode().drain();
        return new SimpleDigestPasswordSpec(getAlgorithmNameString(algorithmId), bytes);
    }

    private static UnixSHACryptPasswordSpec parseUnixSHA256CryptPasswordString(char[] cryptString) throws InvalidKeySpecException {
        assert cryptString[0] == '$'; // previously tested by doIdentifyAlgorithm
        assert cryptString[1] == '5'; // previously tested by doIdentifyAlgorithm
        assert cryptString[2] == '$'; // previously tested by doIdentifyAlgorithm
        return parseUnixSHACryptPasswordSpec(cryptString, SHA_256_IDX_REV, ALGORITHM_CRYPT_SHA_256);
    }

    private static UnixSHACryptPasswordSpec parseUnixSHA512CryptPasswordString(char[] cryptString) throws InvalidKeySpecException {
        assert cryptString[0] == '$'; // previously tested by doIdentifyAlgorithm
        assert cryptString[1] == '6'; // previously tested by doIdentifyAlgorithm
        assert cryptString[2] == '$'; // previously tested by doIdentifyAlgorithm
        return parseUnixSHACryptPasswordSpec(cryptString, SHA_512_IDX_REV, ALGORITHM_CRYPT_SHA_512);
    }

    private static UnixSHACryptPasswordSpec parseUnixSHACryptPasswordSpec(final char[] cryptString, final int[] table, final String algorithm) throws InvalidKeySpecException {
        CodePointIterator r = CodePointIterator.ofChars(cryptString, 3);
        try {
            final int iterationCount; // spec default

            // iteration count
            iterationCount = parseModCryptIterationCount(r, 1_000, 999_999_999, 5_000);

            byte[] salt = r.delimitedBy('$').drainToString().getBytes(StandardCharsets.ISO_8859_1);
            if (! r.hasNext()) {
                throw new InvalidKeySpecException("No salt terminator given");
            }
            r.next(); // skip $
            final byte[] decoded = r.base64Decode(Alphabet.MOD_CRYPT_LE, false).limitedTo(table.length).drain();
            if (decoded.length != table.length) {
                throw new IllegalArgumentException("Invalid hash length");
            }
            byte[] hash = ByteIterator.ofBytes(decoded, table).drain();
            return new UnixSHACryptPasswordSpec(algorithm, hash, salt, iterationCount);
        } catch (NoSuchElementException ignored) {
            throw new InvalidKeySpecException("Unexpected end of password string", ignored);
        }
    }

    private static UnixMD5CryptPasswordSpec parseUnixMD5CryptPasswordString(final char[] cryptString) throws InvalidKeySpecException {
        assert cryptString[0] == '$'; // previously tested by doIdentifyAlgorithm
        assert cryptString[1] == '1'; // previously tested by doIdentifyAlgorithm
        assert cryptString[2] == '$'; // previously tested by doIdentifyAlgorithm
        CodePointIterator r = CodePointIterator.ofChars(cryptString, 3);
        try {
            final byte[] salt = r.delimitedBy('$').drainToString().getBytes(StandardCharsets.ISO_8859_1);
            if (! r.hasNext()) {
                throw new InvalidKeySpecException("No salt terminator given");
            }
            r.next(); // skip $
            final byte[] decoded = r.base64Decode(Alphabet.MOD_CRYPT_LE, false).limitedTo(MD5_IDX_REV.length).drain();
            if (decoded.length != MD5_IDX.length) {
                throw new IllegalArgumentException("Invalid hash length");
            }

            byte[] hash = ByteIterator.ofBytes(decoded, MD5_IDX_REV).drain();
            return new UnixMD5CryptPasswordSpec(hash, salt);
        } catch (NoSuchElementException ignored) {
            throw new InvalidKeySpecException("Unexpected end of password string");
        }
    }

    private static SunUnixMD5CryptPasswordSpec parseSunUnixMD5CryptPasswordString(final String algorithm, final char[] cryptString) throws InvalidKeySpecException {
        assert cryptString[0] == '$'; // previously tested by doIdentifyAlgorithm
        assert cryptString[1] == 'm'; // previously tested by doIdentifyAlgorithm
        assert cryptString[2] == 'd'; // previously tested by doIdentifyAlgorithm
        assert cryptString[3] == '5'; // previously tested by doIdentifyAlgorithm
        assert (cryptString[4] == '$' || cryptString[4] == ','); // previously tested by doIdentifyAlgorithm
        CodePointIterator r = CodePointIterator.ofChars(cryptString, 5);
        try {
            final int iterationCount;
            if (cryptString[4] == ',') {
                // The spec doesn't specify a maximum number of rounds but we're using 2,147,479,551
                // to prevent overflow (2,147,483,647 - 4,096 = 2,147,479,551)
                iterationCount = parseModCryptIterationCount(r, 0, 2_147_479_551, 0);
            } else {
                iterationCount = 0;
            }
            final byte[] salt = r.delimitedBy('$').drainToString().getBytes(StandardCharsets.ISO_8859_1);
            if (! r.hasNext()) {
                throw new InvalidKeySpecException("No salt terminator given");
            }
            r.next();

            // Consume the second '$' after the salt, if present. Note that crypt strings returned
            // by the Sun implementation can have one of the following two formats:
            // 1) $md5[,rounds={rounds}]${salt}$${hash} (this format is more common)
            // 2) $md5[,rounds={rounds}]${salt}${hash} (because there's only a single '$' after the
            //                                          salt, this is referred to as a "bare salt")
            if (algorithm.equals(ALGORITHM_SUN_CRYPT_MD5) && r.hasNext() && r.peekNext() == '$') {
                r.next(); // discard $
            }

            byte[] decoded = r.base64Decode(Alphabet.MOD_CRYPT_LE, false).limitedTo(MD5_IDX_REV.length).drain();
            if (decoded.length != MD5_IDX.length) {
                throw new IllegalArgumentException("Invalid hash length");
            }

            byte[] hash = ByteIterator.ofBytes(decoded, MD5_IDX_REV).drain();
            return new SunUnixMD5CryptPasswordSpec(algorithm, hash, salt, iterationCount);
        } catch (NoSuchElementException ignored) {
            throw new InvalidKeySpecException("Unexpected end of password string");
        }
    }

    private static BCryptPasswordSpec parseBCryptPasswordString(final char[] cryptString) throws InvalidKeySpecException {
        assert cryptString[0] == '$'; // previously tested by doIdentifyAlgorithm
        assert cryptString[1] == '2'; // previously tested by doIdentifyAlgorithm
        char minor = 0;
        if (cryptString[2] != '$') {
            minor = cryptString[2];
            if (minor != 'a' && minor != 'x' && minor != 'y') {
                throw new InvalidKeySpecException("Invalid minor version");
            }
            assert cryptString[3] == '$';
        }

        CodePointIterator r = CodePointIterator.ofChars(cryptString, minor == 0 ? 3 : 4);
        try {
            // read the bcrypt cost (number of rounds in log format)
            int cost = Integer.parseInt(r.limitedTo(2).drainToString());
            if (r.hasNext() && r.peekNext() != '$') {
                throw new InvalidKeySpecException("Invalid cost: must be a two digit integer");
            }
            // discard the '$'
            if (! r.hasNext()) {
                throw new InvalidKeySpecException("Unexpected end of password string");
            }
            r.next();

            // the next 22 characters correspond to the encoded salt - it is mapped to a 16-byte array after decoding.
            byte[] decodedSalt = r.limitedTo(22).base64Decode(Alphabet.BCRYPT, false).drain();

            // the final 31 characters correspond to the encoded password - it is mapped to a 23-byte array after decoding.
            byte[] decodedPassword = r.limitedTo(31).base64Decode(Alphabet.BCRYPT, false).drain();

            return new BCryptPasswordSpec(decodedPassword, decodedSalt, cost);
        } catch (NoSuchElementException ignored) {
            throw new InvalidKeySpecException("Unexpected end of password string");
        }
    }

    private static UnixDESCryptPasswordSpec parseUnixDESCryptPasswordString(char[] cryptString) throws InvalidKeySpecException {
        assert cryptString.length == 13; // previously tested by doIdentifyAlgorithm
        CodePointIterator r = CodePointIterator.ofChars(cryptString);
        // 12 bit salt
        int s0 = Alphabet.MOD_CRYPT.decode(r.next());
        int s1 = Alphabet.MOD_CRYPT.decode(r.next());
        short salt = (short) (s0 | s1 << 6);
        // 64 bit hash
        byte[] hash = r.base64Decode(Alphabet.MOD_CRYPT, false).limitedTo(8).drain();
        return new UnixDESCryptPasswordSpec(hash, salt);
    }

    private static BSDUnixDESCryptPasswordSpec parseBSDUnixDESCryptPasswordString(char[] cryptString) throws InvalidKeySpecException {
        // Note that crypt strings have the format: "_{rounds}{salt}{hash}" as described
        // in the "DES Extended Format" section here: http://www.freebsd.org/cgi/man.cgi?crypt(3)

        assert cryptString.length == 20;
        assert cryptString[0] == '_'; // previously tested by doIdentifyAlgorithm

        CodePointIterator r = CodePointIterator.ofChars(cryptString, 1);

        // The next 4 characters correspond to the encoded number of rounds - this is decoded to a 24-bit integer
        int s0 = Alphabet.MOD_CRYPT.decode(r.next());
        int s1 = Alphabet.MOD_CRYPT.decode(r.next());
        int s2 = Alphabet.MOD_CRYPT.decode(r.next());
        int s3 = Alphabet.MOD_CRYPT.decode(r.next());
        int iterationCount = s0 | s1 << 6 | s2 << 12 | s3 << 18;

        // The next 4 characters correspond to the encoded salt - this is decoded to a 24-bit integer
        s0 = Alphabet.MOD_CRYPT.decode(r.next());
        s1 = Alphabet.MOD_CRYPT.decode(r.next());
        s2 = Alphabet.MOD_CRYPT.decode(r.next());
        s3 = Alphabet.MOD_CRYPT.decode(r.next());
        int salt = s0 | s1 << 6 | s2 << 12 | s3 << 18;

        // The final 11 characters correspond to the encoded password - this is decoded to a 64-bit hash
        byte[] hash = r.base64Decode(Alphabet.MOD_CRYPT, false).limitedTo(11).drain();
        return new BSDUnixDESCryptPasswordSpec(hash, salt, iterationCount);
    }

    private static int indexOf(final char[] chars, final char c) {
        for (int i = 0; i < chars.length; i ++) {
            if (chars[i] == c) return i;
        }
        return -1;
    }

    private static int lastIndexOf(final char[] chars, final char c) {
        for (int i = (chars.length - 1); i >= 0; i--) {
            if (chars[i] == c) return i;
        }
        return -1;
    }

    public static byte[] generateRandomSalt(int saltSize) {
        byte[] randomSalt = new byte[saltSize];
        ThreadLocalRandom.current().nextBytes(randomSalt);
        return randomSalt;
    }

}
