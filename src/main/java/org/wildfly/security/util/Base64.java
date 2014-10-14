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

package org.wildfly.security.util;

import java.io.ByteArrayInputStream;
import java.io.Closeable;
import java.io.IOException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.NoSuchElementException;

import org.wildfly.security.sasl.util.ByteStringBuilder;

/**
 * Utility class for handling Base64 encoded values.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public final class Base64 {

    // Standard Base64 alphabet, as specified in RFC 4648 (http://tools.ietf.org/html/rfc4648)
    private static final char[] STANDARD_ALPHABET = {
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
        'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
        'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
        'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
        'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
        'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
        'w', 'x', 'y', 'z', '0', '1', '2', '3',
        '4', '5', '6', '7', '8', '9', '+', '/'
    };

    // Modular crypt alphabet (used by DES/MD5/SHA crypt)
    private static final char[] MOD_CRYPT_ALPHABET = {
        '.', '/', '0', '1', '2', '3', '4', '5',
        '6', '7', '8', '9', 'A', 'B', 'C', 'D',
        'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L',
        'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
        'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b',
        'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
        'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r',
        's', 't', 'u', 'v', 'w', 'x', 'y', 'z'
    };

    // bcrypt alphabet
    private static final char[] BCRYPT_ALPHABET = {
        '.', '/', 'A', 'B', 'C', 'D', 'E', 'F',
        'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N',
        'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V',
        'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd',
        'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
        'm', 'n', 'o', 'p', 'q', 'r', 's', 't',
        'u', 'v', 'w', 'x', 'y', 'z', '0', '1',
        '2', '3', '4', '5', '6', '7', '8', '9'
    };

    // Lookup tables to be used when decoding characters from the standard, modular crypt, and bcrypt alphabets
    private static final int[] FROM_STANDARD_ALPHABET = getDecodeAlphabet(STANDARD_ALPHABET, true);
    private static final int[] FROM_MOD_CRYPT_ALPHABET = getDecodeAlphabet(MOD_CRYPT_ALPHABET, false);
    private static final int[] FROM_BCRYPT_ALPHABET = getDecodeAlphabet(BCRYPT_ALPHABET, false);

    private static final char PAD = '=';

    /**
     * Get a lookup table that can be used when decoding characters from the given alphabet.
     *
     * @param alphabet the alphabet used for encoding
     * @param includePaddingChar whether or not the padding character, {@code '='}, should be included in the lookup table
     * @return a lookup table that can be used for decoding characters from the given alphabet
     */
    public static int[] getDecodeAlphabet(char[] alphabet, boolean includePaddingChar) {
        int[] decodeAlphabet = new int[256];
        Arrays.fill(decodeAlphabet, -1);

        for (int i = 0; i < alphabet.length; i++) {
            decodeAlphabet[alphabet[i]] = i;
        }
        if (includePaddingChar) {
            decodeAlphabet[PAD] = -2;
        }
        return decodeAlphabet;
    }

    /**
     * Base-64 decode a sequence of characters into an appropriately-sized byte array with an
     * interleave table, using the modular crypt style little-endian scheme.
     *
     * @param reader the character reader
     * @param target the target array
     * @param interleave the interleave table to use
     * @throws InvalidKeySpecException if the end of the sequence of characters is reached unexpectedly
     */
    public static void base64DecodeModCryptLE(CharacterArrayReader reader, byte[] target, int[] interleave) throws InvalidKeySpecException {
        int len = target.length;
        int a, b;
        try {
            for (int i = 0; i < len; ++i) {
                a = base64DecodeModCrypt(reader.read()); // b0[5..0]
                b = base64DecodeModCrypt(reader.read()); // b1[3..0] + b0[7..6]
                target[interleave[i]] = (byte) (a | b << 6); // b0
                if (++i >= len) break;
                a = base64DecodeModCrypt(reader.read()); // b2[1..0] + b1[7..4]
                target[interleave[i]] = (byte) (a << 4 | b >> 2); // b1
                if (++i >= len) break;
                b = base64DecodeModCrypt(reader.read()); // b2[7..2]
                target[interleave[i]] = (byte) (b << 2 | a >> 4); // b2
            }
        } catch (NoSuchElementException | IOException ignored) {
            throw new InvalidKeySpecException("Unexpected end of input string");
        }
    }

    /**
     * Base-64 decode a sequence of characters into an appropriately-sized byte array, using the
     * standard scheme and the given lookup table. The padding character, {@code '='},
     * is allowed at the end of the encoded sequence of characters but it is not required. If a
     * padding character is provided, the correct number of padding characters must be present.
     *
     * @param reader the character reader
     * @param target the target array
     * @param decodeAlphabet the lookup table to use when decoding
     * @throws InvalidKeySpecException if the end of the sequence of characters is reached unexpectedly
     * @throws IllegalArgumentException if the encoded sequence of characters contains an invalid number of padding characters
     */
    public static void base64Decode(CharacterArrayReader reader, byte[] target, int[] decodeAlphabet) throws InvalidKeySpecException, IllegalArgumentException {
        int len = target.length;
        int a, b;
        try{
            for (int i = 0; i < len; ++i) {
                a = base64Decode(reader.read(), decodeAlphabet);
                if (a == -2) throw unexpectedPadding();
                b = base64Decode(reader.read(), decodeAlphabet);
                if (b == -2) throw unexpectedPadding();
                target[i] = (byte) (a << 2 | b >> 4);
                if (++i >= len) break;
                a = base64Decode(reader.read(), decodeAlphabet);
                if (a == -2) {
                    // If a padding character is found, the correct number of padding characters should be present
                    if (base64Decode(reader.read(), decodeAlphabet) != -2) {
                        throw missingRequiredPadding();
                    }
                } else {
                    target[i] = (byte) (b << 4 | a >> 2);
                    if (++i >= len) break;
                    if ((b = base64Decode(reader.read(), decodeAlphabet)) != -2) {
                        target[i] = (byte) (a << 6 | b >> 0);
                    }
                }
            }
        } catch (NoSuchElementException | IOException ignored) {
            throw new InvalidKeySpecException("Unexpected end of input string");
        }
    }

    /**
     * Base-64 decode a sequence of characters into a newly created byte array, starting from the given offset,
     * using the standard scheme and the given alphabet. The padding character, {@code '='}, is allowed at the
     * end of the encoded sequence of characters but it is not required. If a padding character is provided, the
     * correct number of padding characters must be present.
     *
     * @param encoded the characters to decode
     * @param offset the offset of the first character to decode
     * @param len the number of characters to decode
     * @param decodeAlphabet the lookup table to use when decoding
     * @return an appropriately-sized byte array containing the decoded bytes
     * @throws InvalidKeySpecException if the end of the sequence of characters is reached unexpectedly
     * @throws IllegalArgumentException if the encoded sequence of characters contains an invalid number of padding characters
     */
    public static byte[] base64Decode(char[] encoded, int offset, int len, int[] decodeAlphabet) throws InvalidKeySpecException, IllegalArgumentException {
        int decodedLen = calculateDecodedLength(encoded, offset, len);
        byte[] target = new byte[decodedLen];
        CharacterArrayReader r = new CharacterArrayReader(encoded, offset, len);
        try {
            base64Decode(r, target, decodeAlphabet);
        } finally {
            safeClose(r);
        }
        return target;
    }

    /**
     * Base-64 decode a sequence of characters into a newly created byte array, starting from the given offset,
     * using the standard scheme and the given alphabet. The padding character, {@code '='}, is allowed at the
     * end of the encoded sequence of characters but it is not required. If a padding character is provided, the
     * correct number of padding characters must be present.
     *
     * @param encoded the characters to decode
     * @param offset the offset of the first character to decode
     * @param decodeAlphabet the lookup table to use when decoding
     * @return an appropriately-sized byte array containing the decoded bytes
     * @throws InvalidKeySpecException if the end of the sequence of characters is reached unexpectedly
     * @throws IllegalArgumentException if the encoded sequence of characters contains an invalid number of padding characters
     */
    public static byte[] base64Decode(char[] encoded, int offset, int[] decodeAlphabet) throws InvalidKeySpecException, IllegalArgumentException {
        return base64Decode(encoded, offset, encoded.length - offset, decodeAlphabet);
    }

    /**
     * Base-64 decode a sequence of bytes into the given {@code ByteStringBuilder}, starting from the
     * given offset, using the standard scheme and the given alphabet. The padding character, {@code '='},
     * is allowed at the end of the encoded sequence of bytes but it is not required. If a padding
     * character is provided, the correct number of padding characters must be present.
     *
     * @param encoded the bytes to decode
     * @param offset the offset of the first byte to decode
     * @param len the number of bytes to decode
     * @param target the target byte string builder
     * @param decodeAlphabet the lookup table to use when decoding
     * @return the number of bytes that were decoded
     * @throws InvalidKeySpecException if the end of the sequence of bytes is reached unexpectedly
     * @throws IllegalArgumentException if the encoded sequence of bytes contains an invalid number of padding characters
     */
    public static int base64Decode(byte[] encoded, int offset, int len, ByteStringBuilder target, int[] decodeAlphabet) throws InvalidKeySpecException, IllegalArgumentException {
        int count = 0;
        int t1, t2;
        while (count < len) {
            // top 6 bits of the first byte
            t1 = base64Decode(encoded[offset + count++], decodeAlphabet);
            if (t1 == -1) return count - 1;
            if (t1 == -2) throw unexpectedPadding();
            if (count == len) throw truncatedInput();

            // bottom 2 bits + top 4 bits of the second byte
            t2 = base64Decode(encoded[offset + count++], decodeAlphabet);
            if (t2 == -1) throw truncatedInput();
            if (t2 == -2) throw unexpectedPadding();
            if (count == len) throw truncatedInput();
            target.append((byte)((t1 & 0xff) << 2 | (t2 & 0xff) >>> 4));

            // bottom 4 bits + top 4 bits of the third byte - or == if it's the end
            t1 = base64Decode(encoded[offset + count++], decodeAlphabet);
            if (t1 == -1) throw truncatedInput();
            if (count == len) throw truncatedInput();
            if (t1 == -2) {
                // expect one more byte of padding
                assert count < len;
                if (encoded[offset + count++] != PAD) {
                    throw missingRequiredPadding();
                }
                return count;
            }
            target.append((byte) ((t2 & 0xff) << 4 | (t1 & 0xff) >>> 2));

            // top 2 bits of the third byte + bottom 6 bits of the fourth byte - or = if it's the end
            t2 = base64Decode(encoded[offset + count++], decodeAlphabet);
            if (t2 == -1) throw truncatedInput();
            if (t2 == -2) return count;
            target.append((byte) ((t1 & 0xff) << 6 | t2));
        }
        return count;
    }

    /**
     * Base-64 decode a single character using the given lookup table.
     *
     * @param ch the character
     * @param decodeAlphabet the lookup table to use when decoding
     * @return the byte
     * @throws InvalidKeySpecException if the character is not in the alphabet
     */
    public static int base64Decode(int ch, int[] decodeAlphabet) throws InvalidKeySpecException {
        int decoded = decodeAlphabet[ch];
        if (decoded == -1) {
            throw new InvalidKeySpecException("Invalid character encountered");
        }
        return decoded;
    }

    /**
     * Base-64 decode a sequence of characters into an appropriately-sized byte array, using the
     * standard scheme and the modular crypt alphabet.
     *
     * @param reader the character reader
     * @param target the target array
     * @throws InvalidKeySpecException if the end of the sequence of characters is reached unexpectedly
     */
    public static void base64DecodeModCrypt(CharacterArrayReader reader, byte[] target) throws InvalidKeySpecException {
        base64Decode(reader, target, FROM_MOD_CRYPT_ALPHABET);
    }

    /**
     * Base-64 decode a sequence of characters into an appropriately-sized byte array, using the standard
     * scheme and the standard alphabet. The padding character, {@code '='}, is allowed at the end of the
     * encoded sequence of characters but it is not required. If a padding character is provided, the correct
     * number of padding characters must be present.
     *
     * @param reader the character reader
     * @param target the target array
     * @throws InvalidKeySpecException if the end of the sequence of characters is reached unexpectedly
     * @throws IllegalArgumentException if the encoded sequence of characters contains an invalid number of padding characters
     */
    public static void base64DecodeStandard(CharacterArrayReader reader, byte[] target) throws InvalidKeySpecException, IllegalArgumentException {
        base64Decode(reader, target, FROM_STANDARD_ALPHABET);
    }

    /**
     * Base-64 decode a sequence of characters into a newly created byte array, starting from the given offset,
     * using the standard scheme and the standard alphabet. The padding character, {@code '='}, is allowed at the
     * end of the encoded sequence of characters but it is not required. If a padding character is provided, the
     * correct number of padding characters must be present.
     *
     * @param encoded the characters to decode
     * @param offset the offset of the first character to decode
     * @param len the number of characters to decode
     * @return an appropriately-sized byte array containing the decoded bytes
     * @throws InvalidKeySpecException if the end of the sequence of characters is reached unexpectedly
     * @throws IllegalArgumentException if the encoded sequence of characters contains an invalid number of padding characters
     */
    public static byte[] base64DecodeStandard(char[] encoded, int offset, int len) throws InvalidKeySpecException, IllegalArgumentException {
        return base64Decode(encoded, offset, len, FROM_STANDARD_ALPHABET);
    }

    /**
     * Base-64 decode a sequence of characters into a newly created byte array, starting from the given offset,
     * using the standard scheme and the standard alphabet. The padding character, {@code '='}, is allowed at the
     * end of the encoded sequence of characters but it is not required. If a padding character is provided, the
     * correct number of padding characters must be present.
     *
     * @param encoded the characters to decode
     * @param offset the offset of the first character to decode
     * @return an appropriately-sized byte array containing the decoded bytes
     * @throws InvalidKeySpecException if the end of the sequence of characters is reached unexpectedly
     * @throws IllegalArgumentException if the encoded sequence of characters contains an invalid number of padding characters
     */
    public static byte[] base64DecodeStandard(char[] encoded, int offset) throws InvalidKeySpecException, IllegalArgumentException {
        return base64Decode(encoded, offset, FROM_STANDARD_ALPHABET);
    }

    /**
     * Base-64 decode a sequence of bytes into the given {@code ByteStringBuilder}, starting from the
     * given offset, using the standard scheme and the standard alphabet. The padding character, {@code '='},
     * is allowed at the end of the encoded sequence of bytes but it is not required. If a padding
     * character is provided, the correct number of padding characters must be present.
     *
     * @param encoded the bytes to decode
     * @param offset the offset of the first byte to decode
     * @param len the number of bytes to decode
     * @param target the target byte string builder
     * @return the number of bytes that were decoded
     * @throws InvalidKeySpecException if the end of the sequence of bytes is reached unexpectedly
     * @throws IllegalArgumentException if the encoded sequence of bytes contains an invalid number of padding characters
     */
    public static int base64DecodeStandard(byte[] encoded, int offset, int len, ByteStringBuilder target) throws InvalidKeySpecException, IllegalArgumentException {
        return base64Decode(encoded, offset, len, target, FROM_STANDARD_ALPHABET);
    }

    /**
     * Base-64 decode a sequence of bytes into the given {@code ByteStringBuilder}, starting from the
     * given offset, using the standard scheme and the standard alphabet. The padding character, {@code '='},
     * is allowed at the end of the encoded sequence of bytes but it is not required. If a padding
     * character is provided, the correct number of padding characters must be present.
     *
     * @param encoded the bytes to decode
     * @param offset the offset of the first byte to decode
     * @param target the target byte string builder
     * @return the number of bytes that were decoded
     * @throws InvalidKeySpecException if the end of the sequence of bytes is reached unexpectedly
     * @throws IllegalArgumentException if the encoded sequence of bytes contains an invalid number of padding characters
     */
    public static int base64DecodeStandard(byte[] encoded, int offset, ByteStringBuilder target) throws InvalidKeySpecException, IllegalArgumentException {
        return base64DecodeStandard(encoded, offset, encoded.length - offset, target);
    }

    /**
     * Base-64 decode a sequence of characters into an appropriately-sized byte array, using the standard scheme and
     * the bcrypt alphabet.
     *
     * @param reader the character reader
     * @param target the target array
     * @throws InvalidKeySpecException if the end of the sequence of characters is reached unexpectedly
     */
    public static void base64DecodeBCrypt(CharacterArrayReader reader, byte[] target) throws InvalidKeySpecException {
        base64Decode(reader, target, FROM_BCRYPT_ALPHABET);
    }

    /**
     * Base-64 decode a single character with the modular crypt alphabet (DES/MD5/SHA crypt).
     *
     * @param ch the character
     * @return the byte
     * @throws InvalidKeySpecException if the character is not in the alphabet
     */
    public static int base64DecodeModCrypt(int ch) throws InvalidKeySpecException {
        return base64Decode(ch, FROM_MOD_CRYPT_ALPHABET);
    }

    /**
     * Base-64 decode a single character with the standard Base64 alphabet, as
     * specified in Table 1 in <a href="http://tools.ietf.org/html/rfc4648"> RFC 4648</a>.
     *
     * @param ch the character
     * @return the byte
     * @throws InvalidKeySpecException if the character is not in the alphabet
     */
    private static int base64DecodeStandard(int ch) throws InvalidKeySpecException {
        return base64Decode(ch, FROM_STANDARD_ALPHABET);
    }

    /**
     * Base-64 decode a single character with the bcrypt alphabet.
     *
     * @param ch the character
     * @return the byte
     * @throws InvalidKeySpecException if the character is not in the alphabet
     */
    private static int base64DecodeBCrypt(int ch) throws InvalidKeySpecException {
        return base64Decode(ch, FROM_BCRYPT_ALPHABET);
    }

    /**
     * Base-64 encode a sequence of bytes into the given {@code StringBuilder} using the standard
     * scheme and the given alphabet.
     *
     * @param target the target string builder
     * @param src the source byte array input stream to encode
     * @param alphabet the alphabet to use when encoding
     * @param doPadding whether or not padding characters should be appended to the encoded result
     */
    public static void base64Encode(StringBuilder target, ByteArrayInputStream src, char[] alphabet, boolean doPadding) {
        int a, b;
        while ((a = src.read()) != -1) {
            base64Encode(target, a >> 2, alphabet); // top 6 bits
            if ((b = src.read()) == -1) {
                base64Encode(target, a << 4, alphabet); // bottom 2 bits + 0000
                if (doPadding) {
                    target.append(PAD).append(PAD);
                }
                return;
            }
            base64Encode(target, (a & 0b11) << 4 | b >> 4, alphabet); // bottom 2 bits + top 4 bits
            if ((a = src.read()) == -1) {
                base64Encode(target, b << 2, alphabet); // bottom 4 bits + 00
                if (doPadding) {
                    target.append(PAD);
                }
                return;
            }
            base64Encode(target, b << 2 | a >> 6, alphabet); // bottom 4 bits + top 2 bits
            base64Encode(target, a, alphabet); // bottom 6 bits
        }
    }

    /**
     * Base-64 encode a sequence of bytes into the given {@code ByteStringBuilder} using the standard
     * scheme and the given alphabet.
     *
     * @param target the target byte string builder
     * @param src the source byte array input stream to encode
     * @param alphabet the alphabet to use when encoding
     * @param doPadding whether or not padding characters should be appended to the encoded result
     */
    public static void base64Encode(ByteStringBuilder target, ByteArrayInputStream src, char[] alphabet, boolean doPadding) {
        int a, b;
        while ((a = src.read()) != -1) {
            base64Encode(target, a >> 2, alphabet); // top 6 bits
            if ((b = src.read()) == -1) {
                base64Encode(target, a << 4, alphabet); // bottom 2 bits + 0000
                if (doPadding) {
                    target.append(PAD).append(PAD);
                }
                return;
            }
            base64Encode(target, (a & 0b11) << 4 | b >> 4, alphabet); // bottom 2 bits + top 4 bits
            if ((a = src.read()) == -1) {
                base64Encode(target, b << 2, alphabet); // bottom 4 bits + 00
                if (doPadding) {
                    target.append(PAD);
                }
                return;
            }
            base64Encode(target, b << 2 | a >> 6, alphabet); // bottom 4 bits + top 2 bits
            base64Encode(target, a, alphabet); // bottom 6 bits
        }
    }

    /**
     * Base-64 encode a single byte with the given alphabet and append the resulting
     * character to the given {@code StringBuilder}.
     *
     * @param target the target string builder
     * @param a the byte
     * @param alphabet the alphabet to use when encoding
     */
    public static void base64Encode(StringBuilder target, int a, char[] alphabet) {
        a &= 0b0011_1111;
        target.append(alphabet[a]);
    }

    /**
     * Base-64 encode a single byte with the given alphabet and append the resulting
     * character to the given {@code ByteStringBuilder}.
     *
     * @param target the target byte string builder
     * @param a the byte
     * @param alphabet the alphabet to use when encoding
     */
    public static void base64Encode(ByteStringBuilder target, int a, char[] alphabet) {
        a &= 0b0011_1111;
        target.append(alphabet[a]);
    }

    /**
     * Base-64 encode a sequence of bytes into the given {@code StringBuilder} using the standard
     * scheme and modular crypt alphabet.
     *
     * @param target the target string builder
     * @param src the source byte array input stream to encode
     */
    public static void base64EncodeModCrypt(StringBuilder target, ByteArrayInputStream src) {
        base64Encode(target, src, MOD_CRYPT_ALPHABET, false);
    }

    /**
     * Base-64 encode a sequence of bytes into the given {@code StringBuilder} using the standard
     * scheme and the standard alphabet but do not include padding characters at the end of the
     * encoded result.
     *
     * @param target the target string builder
     * @param src the source byte array input stream to encode
     */
    public static void base64EncodeStandard(StringBuilder target, ByteArrayInputStream src) {
        base64Encode(target, src, STANDARD_ALPHABET, false);
    }

    /**
     * Base-64 encode a sequence of bytes into the given {@code StringBuilder} using the standard
     * scheme and the standard alphabet and optionally include padding characters at the end of the
     * encoded result.
     *
     * @param target the target string builder
     * @param src the source byte array input stream to encode
     * @param doPadding whether or not padding characters should be appended to the encoded result
     */
    public static void base64EncodeStandard(StringBuilder target, ByteArrayInputStream src, boolean doPadding) {
        base64Encode(target, src, STANDARD_ALPHABET, doPadding);
    }

    /**
     * Base-64 encode a sequence of bytes into the given {@code ByteStringBuilder} using the standard
     * scheme and the standard alphabet and optionally include padding characters at the end of the encoded result.
     *
     * @param target the target byte string builder
     * @param src the source byte array to encode
     * @param doPadding whether or not padding characters should be appended to the encoded result
     */
    public static void base64EncodeStandard(ByteStringBuilder target, ByteArrayInputStream src, boolean doPadding) {
        base64Encode(target, src, STANDARD_ALPHABET, doPadding);
    }

    /**
     * Base-64 encode a sequence of bytes into the given {@code StringBuilder} using the standard
     * scheme and the bcrypt alphabet.
     *
     * @param target the target string builder
     * @param src the source byte array input stream to encode
     */
    public static void base64EncodeBCrypt(StringBuilder target, ByteArrayInputStream src) {
        base64Encode(target, src, BCRYPT_ALPHABET, false);
    }

    /**
     * Base-64 encode a sequence of bytes into the given {@code StringBuilder} using the modular
     * crypt style little-endian scheme.
     *
     * @param target the target string builder
     * @param src the source byte array input stream to encode
     */
    public static void base64EncodeModCryptLE(StringBuilder target, ByteArrayInputStream src) {
        // A detailed description of the encoding scheme used here can be found in:
        // ftp://ftp.arlut.utexas.edu/pub/java_hashes/SHA-crypt.txt
        int a, b;
        while ((a = src.read()) != -1) {
            base64EncodeModCrypt(target, a); // b0[5..0]
            if ((b = src.read()) == -1) {
                base64EncodeModCrypt(target, a >> 6); // 0000 + b0[7..6]
                return;
            }
            base64EncodeModCrypt(target, b << 2 | a >> 6); // b1[3..0] + b0[7..6]
            if ((a = src.read()) == -1) {
                base64EncodeModCrypt(target, b >> 4); // 00 + b1[7..4]
                return;
            }
            base64EncodeModCrypt(target, a << 4 | b >> 4); // b2[1..0] + b1[7..4]
            base64EncodeModCrypt(target, a >> 2); // b2[7..2]
        }
    }

    /**
     * Base-64 encode a single byte with the modular crypt alphabet (DES/MD5/SHA crypt) and append
     * the resulting character to the given {@code StringBuilder}.
     *
     * @param target the target string builder
     * @param a the byte
     */
    public static void base64EncodeModCrypt(StringBuilder target, int a) {
        base64Encode(target, a, MOD_CRYPT_ALPHABET);
    }

    /**
     * Base-64 encode a single byte with the standard Base64 alphabet, as specified in Table 1
     * in <a href="http://tools.ietf.org/html/rfc4648"> RFC 4648</a>, and append the resulting
     * character to the given {@code StringBuilder}.
     *
     * @param target the target string builder
     * @param a the byte
     */
    public static void base64EncodeStandard(StringBuilder target, int a) {
        base64Encode(target, a, STANDARD_ALPHABET);
    }

    /**
     * Base-64 encode a single byte with the bcrypt alphabet and append the resulting character
     * to the given {@code StringBuilder}.
     *
     * @param target the target string builder
     * @param a the byte
     */
    public static void base64EncodeBCrypt(StringBuilder target, int a) {
        base64Encode(target, a, BCRYPT_ALPHABET);
    }

    /**
     * Calculate the number of bytes that will be needed to store the result of Base-64 decoding
     * the given sequence of characters using the given offset and length. The padding character,
     * {@code '='}, is allowed in the encoded sequence of characters but it is not required.
     *
     * @param encoded the characters that will be decoded
     * @param offset the offset of the first character that will be decoded
     * @param len the number of characters that will be decoded
     * @return the size of the byte array that will be needed to store the decoded bytes
     */
    public static int calculateDecodedLength(char[] encoded, int offset, int len) {
        if (len == 0) {
            return 0;
        }

        // Determine if padding characters are present
        int numPaddings = 0;
        if (encoded[offset + len - 1] == PAD) {
            numPaddings = 1;
            if (len >= 2 && encoded[offset + len - 2] == PAD) {
                numPaddings = 2;
            }
        }

        int remainder = len % 4;
        if ((numPaddings == 0) && (remainder != 0)) {
            numPaddings = 4 - remainder;
        }
        return (((len + 3) / 4) * 3) - numPaddings;
    }

    private static void safeClose(Closeable c) {
        if (c != null) {
            try {
                c.close();
            } catch (Throwable ignored) {}
        }
    }

    private static IllegalArgumentException missingRequiredPadding() {
        return new IllegalArgumentException("Missing required padding");
    }

    private static IllegalArgumentException unexpectedPadding() {
        return new IllegalArgumentException("Unexpected padding");
    }

    private static IllegalArgumentException truncatedInput() {
        return new IllegalArgumentException("Truncated input");
    }
}
