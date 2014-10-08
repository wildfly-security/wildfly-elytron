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
import static org.wildfly.security.util.Base64.*;

import java.io.ByteArrayInputStream;
import java.io.Closeable;
import java.io.IOException;
import java.security.spec.InvalidKeySpecException;
import java.util.Locale;
import java.util.NoSuchElementException;

import org.wildfly.security.password.interfaces.BCryptPassword;
import org.wildfly.security.password.interfaces.BSDUnixDESCryptPassword;
import org.wildfly.security.password.spec.BCryptPasswordSpec;
import org.wildfly.security.password.spec.BSDUnixDESCryptPasswordSpec;
import org.wildfly.security.password.spec.PasswordSpec;
import org.wildfly.security.password.spec.SunUnixMD5CryptPasswordSpec;
import org.wildfly.security.password.spec.TrivialDigestPasswordSpec;
import org.wildfly.security.password.spec.UnixDESCryptPasswordSpec;
import org.wildfly.security.password.spec.UnixMD5CryptPasswordSpec;
import org.wildfly.security.password.spec.UnixSHACryptPasswordSpec;
import org.wildfly.security.util.CharacterArrayReader;

/**
 * General password utilities.
 *
 * @author <a href="mailto:jpkroehling.javadoc@redhat.com">Juraci Paixão Kröhling</a>
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class PasswordUtils {
    private PasswordUtils() {}

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
            base64EncodeBCrypt(b, new ByteArrayInputStream(spec.getSalt()));
            base64EncodeBCrypt(b, new ByteArrayInputStream(spec.getHashBytes()));
        } else if (passwordSpec instanceof BSDUnixDESCryptPasswordSpec) {
            b.append("_");
            final BSDUnixDESCryptPasswordSpec spec = (BSDUnixDESCryptPasswordSpec) passwordSpec;
            final int iterationCount = spec.getIterationCount();
            base64EncodeModCrypt(b, iterationCount);
            base64EncodeModCrypt(b, iterationCount >> 6);
            base64EncodeModCrypt(b, iterationCount >> 12);
            base64EncodeModCrypt(b, iterationCount >> 18);
            final int salt = spec.getSalt();
            base64EncodeModCrypt(b, salt);
            base64EncodeModCrypt(b, salt >> 6);
            base64EncodeModCrypt(b, salt >> 12);
            base64EncodeModCrypt(b, salt >> 18);
            base64EncodeModCrypt(b, new ByteArrayInputStream(spec.getHash()));
        } else if (passwordSpec instanceof TrivialDigestPasswordSpec) {
            final TrivialDigestPasswordSpec spec = (TrivialDigestPasswordSpec) passwordSpec;
            final String algorithm = spec.getAlgorithm();
            b.append('[').append(algorithm).append(']');
            base64EncodeStandard(b, new ByteArrayInputStream(spec.getDigest()));
        } else if (passwordSpec instanceof UnixDESCryptPasswordSpec) {
            final UnixDESCryptPasswordSpec spec = (UnixDESCryptPasswordSpec) passwordSpec;
            final short salt = spec.getSalt();
            base64EncodeModCrypt(b, salt);
            base64EncodeModCrypt(b, salt >> 6);
            base64EncodeModCrypt(b, new ByteArrayInputStream(spec.getHash()));
        } else if (passwordSpec instanceof UnixMD5CryptPasswordSpec) {
            b.append("$1$");
            final UnixMD5CryptPasswordSpec spec = (UnixMD5CryptPasswordSpec) passwordSpec;
            final byte[] salt = spec.getSalt();
            for (final byte sb : salt) {
                b.append((char) (sb & 0xff));
            }
            b.append('$');
            base64EncodeModCryptLE(b, new IByteArrayInputStream(spec.getHash(), MD5_IDX));
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
            base64EncodeModCryptLE(b, new IByteArrayInputStream(spec.getHash(), MD5_IDX));
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
            base64EncodeModCryptLE(b, new IByteArrayInputStream(spec.getHash(), interleave));
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
                return parseTrivialDigestPasswordString(algorithmId, cryptString);
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

    private static int parseModCryptIterationCount(final CharacterArrayReader reader, final int minIterations, final int maxIterations,
            final int defaultIterations) throws InvalidKeySpecException {
        int iterationCount;
        try {
            if (reader.contentEquals("rounds=")) {
                reader.skip(7);
                iterationCount = 0;
                for (int ch = reader.read(); ch != '$'; ch = reader.read()) {
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
            } else {
                iterationCount = defaultIterations;
            }
        } catch (NoSuchElementException | IOException ignored) {
            throw new InvalidKeySpecException("Unexpected end of input string");
        }
        return max(minIterations, iterationCount);
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
        byte[] bytes = base64DecodeStandard(cryptString, initialLen);
        return new TrivialDigestPasswordSpec(getAlgorithmNameString(algorithmId), bytes);
    }

    private static UnixSHACryptPasswordSpec parseUnixSHA256CryptPasswordString(char[] cryptString) throws InvalidKeySpecException {
        assert cryptString[0] == '$'; // previously tested by doIdentifyAlgorithm
        assert cryptString[1] == '5'; // previously tested by doIdentifyAlgorithm
        assert cryptString[2] == '$'; // previously tested by doIdentifyAlgorithm
        return parseUnixSHACryptPasswordSpec(cryptString, SHA_256_IDX, ALGORITHM_CRYPT_SHA_256);
    }

    private static UnixSHACryptPasswordSpec parseUnixSHA512CryptPasswordString(char[] cryptString) throws InvalidKeySpecException {
        assert cryptString[0] == '$'; // previously tested by doIdentifyAlgorithm
        assert cryptString[1] == '6'; // previously tested by doIdentifyAlgorithm
        assert cryptString[2] == '$'; // previously tested by doIdentifyAlgorithm
        return parseUnixSHACryptPasswordSpec(cryptString, SHA_512_IDX, ALGORITHM_CRYPT_SHA_512);
    }

    private static UnixSHACryptPasswordSpec parseUnixSHACryptPasswordSpec(final char[] cryptString, final int[] table, final String algorithm) throws InvalidKeySpecException {
        CharacterArrayReader r = new CharacterArrayReader(cryptString, 3);
        try {
            final int iterationCount; // spec default

            // iteration count
            iterationCount = parseModCryptIterationCount(r, 1_000, 999_999_999, 5_000);

            int saltByteLen = r.distanceTo('$');
            if (saltByteLen == -1) {
                throw new InvalidKeySpecException("No salt terminator given");
            }

            byte[] salt = new byte[saltByteLen];
            int b = r.read();
            int j = 0;
            while (b != '$') {
                salt[j++] = (byte) b;
                b = r.read();
            }

            byte[] hash = new byte[table.length]; // key size == table length
            base64DecodeModCryptLE(r, hash, table);

            return new UnixSHACryptPasswordSpec(algorithm, hash, salt, iterationCount);
        } catch (NoSuchElementException | IOException ignored) {
            throw new InvalidKeySpecException("Unexpected end of password string");
        } finally {
            safeClose(r);
        }
    }

    private static UnixMD5CryptPasswordSpec parseUnixMD5CryptPasswordString(final char[] cryptString) throws InvalidKeySpecException {
        assert cryptString[0] == '$'; // previously tested by doIdentifyAlgorithm
        assert cryptString[1] == '1'; // previously tested by doIdentifyAlgorithm
        assert cryptString[2] == '$'; // previously tested by doIdentifyAlgorithm
        CharacterArrayReader r = new CharacterArrayReader(cryptString, 3);
        try {
            int saltByteLen = r.distanceTo('$');
            if (saltByteLen == -1) {
                throw new InvalidKeySpecException("No salt terminator given");
            }

            byte[] salt = new byte[saltByteLen];
            int b = r.read();
            int j = 0;
            while (b != '$') {
                salt[j++] = (byte) b;
                b = r.read();
            }

            byte[] hash = new byte[MD5_IDX.length]; // key size == table length
            base64DecodeModCryptLE(r, hash, MD5_IDX);

            return new UnixMD5CryptPasswordSpec(hash, salt);
        } catch (NoSuchElementException | IOException ignored) {
            throw new InvalidKeySpecException("Unexpected end of password string");
        } finally {
            safeClose(r);
        }
    }

    private static SunUnixMD5CryptPasswordSpec parseSunUnixMD5CryptPasswordString(final String algorithm, final char[] cryptString) throws InvalidKeySpecException {
        assert cryptString[0] == '$'; // previously tested by doIdentifyAlgorithm
        assert cryptString[1] == 'm'; // previously tested by doIdentifyAlgorithm
        assert cryptString[2] == 'd'; // previously tested by doIdentifyAlgorithm
        assert cryptString[3] == '5'; // previously tested by doIdentifyAlgorithm
        assert (cryptString[4] == '$' || cryptString[4] == ','); // previously tested by doIdentifyAlgorithm
        CharacterArrayReader r = new CharacterArrayReader(cryptString, 5);
        try {
            final int iterationCount;
            if (cryptString[4] == ',') {
                // The spec doesn't specify a maximum number of rounds but we're using 2,147,479,551
                // to prevent overflow (2,147,483,647 - 4,096 = 2,147,479,551)
                iterationCount = parseModCryptIterationCount(r, 0, 2_147_479_551, 0);
            } else {
                iterationCount = 0;
            }
            int saltByteLen = r.distanceTo('$');
            if (saltByteLen == -1) {
                throw new InvalidKeySpecException("No salt terminator given");
            }

            byte[] salt = new byte[saltByteLen];
            int b = r.read();
            int j = 0;
            while (b != '$') {
                salt[j++] = (byte) b;
                b = r.read();
            }

            // Consume the second '$' after the salt, if present. Note that crypt strings returned
            // by the Sun implementation can have one of the following two formats:
            // 1) $md5[,rounds={rounds}]${salt}$${hash} (this format is more common)
            // 2) $md5[,rounds={rounds}]${salt}${hash} (because there's only a single '$' after the
            //                                          salt, this is referred to as a "bare salt")
            if (algorithm.equals(ALGORITHM_SUN_CRYPT_MD5)) {
                b = r.read();
                assert b == '$'; // previously tested by doIdentifyAlgorithm
            }

            byte[] hash = new byte[MD5_IDX.length]; // key size == table length
            base64DecodeModCryptLE(r, hash, MD5_IDX);

            return new SunUnixMD5CryptPasswordSpec(algorithm, hash, salt, iterationCount);
        } catch (NoSuchElementException | IOException ignored) {
            throw new InvalidKeySpecException("Unexpected end of password string");
        } finally {
            safeClose(r);
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

        CharacterArrayReader r = null;
        try {
            // read the bcrypt cost (number of rounds in log format)
            r = new CharacterArrayReader(cryptString, minor == 0 ? 3 : 4);
            int costLength = r.distanceTo('$');
            if (costLength != 2) {
                throw new InvalidKeySpecException("Invalid cost: must be a two digit integer");
            }
            char[] costDigits = new char[2];
            costDigits[0] = (char) r.read();
            costDigits[1] = (char) r.read();
            int cost = Integer.parseInt(new String(costDigits));
            // discard the '$'
            r.skip(1);

            // the next 22 characters correspond to the encoded salt - it is mapped to a 16-byte array after decoding.
            byte[] decodedSalt = new byte[BCryptPassword.BCRYPT_SALT_SIZE];
            base64DecodeBCrypt(r, decodedSalt);

            // the final 31 characters correspond to the encoded password - it is mapped to a 23-byte array after decoding.
            byte[] decodedPassword = new byte[BCryptPassword.BCRYPT_HASH_SIZE];
            base64DecodeBCrypt(r, decodedPassword);

            return new BCryptPasswordSpec(decodedPassword, decodedSalt, cost);
        } catch (NoSuchElementException | IOException ignored) {
            throw new InvalidKeySpecException("Unexpected end of password string");
        } finally {
            safeClose(r);
        }
    }

    private static UnixDESCryptPasswordSpec parseUnixDESCryptPasswordString(char[] cryptString) throws InvalidKeySpecException {
        assert cryptString.length == 13; // previously tested by doIdentifyAlgorithm
        // 12 bit salt
        short salt = (short) (base64DecodeModCrypt(cryptString[0]) | base64DecodeModCrypt(cryptString[1]) << 6);
        // 64 bit hash
        byte[] hash = new byte[8];
        CharacterArrayReader r = new CharacterArrayReader(cryptString, 2);
        try {
            base64DecodeModCrypt(r, hash);
        } finally {
            safeClose(r);
        }
        return new UnixDESCryptPasswordSpec(hash, salt);
    }

    private static BSDUnixDESCryptPasswordSpec parseBSDUnixDESCryptPasswordString(char[] cryptString) throws InvalidKeySpecException {
        // Note that crypt strings have the format: "_{rounds}{salt}{hash}" as described
        // in the "DES Extended Format" section here: http://www.freebsd.org/cgi/man.cgi?crypt(3)

        assert cryptString.length == 20;
        assert cryptString[0] == '_'; // previously tested by doIdentifyAlgorithm

        // The next 4 characters correspond to the encoded number of rounds - this is decoded to a 24-bit integer
        int iterationCount = base64DecodeModCrypt(cryptString[1]) | base64DecodeModCrypt(cryptString[2]) << 6 | base64DecodeModCrypt(cryptString[3]) << 12 | base64DecodeModCrypt(cryptString[4]) << 18;

        // The next 4 characters correspond to the encoded salt - this is decoded to a 24-bit integer
        int salt = base64DecodeModCrypt(cryptString[5]) | base64DecodeModCrypt(cryptString[6]) << 6 | base64DecodeModCrypt(cryptString[7]) << 12 | base64DecodeModCrypt(cryptString[8]) << 18;

        // The final 11 characters correspond to the encoded password - this is decoded to a 64-bit hash
        byte[] hash = new byte[BSDUnixDESCryptPassword.BSD_CRYPT_DES_HASH_SIZE];
        CharacterArrayReader r = new CharacterArrayReader(cryptString, 9);
        try {
            base64DecodeModCrypt(r, hash);
        } finally {
            safeClose(r);
        }
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

    private static void safeClose(Closeable c) {
        if (c != null) {
            try {
                c.close();
            } catch (Throwable ignored) {}
        }
    }
}
