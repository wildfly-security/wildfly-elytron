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

import java.security.spec.InvalidKeySpecException;
import java.util.NoSuchElementException;

/**
 * Utility class for handling Base64 encoded values.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public final class Base64 {

    /**
     * Base-64 decode a sequence of characters into an appropriately-sized byte array at the given offset with an
     * interleave table, using the modular crypt style little-endian scheme.
     *
     * @param iter the character iterator
     * @param target the target array
     * @param interleave the interleave table to use
     */
    public static void base64DecodeACryptLE(CharacterArrayIterator iter, byte[] target, int[] interleave) throws InvalidKeySpecException {
        int len = target.length;
        int a, b;
        try {
            for (int i = 0; i < len; ++i) {
                a = base64DecodeA(iter.next()); // b0[5..0]
                b = base64DecodeA(iter.next()); // b1[3..0] + b0[7..6]
                target[interleave[i]] = (byte) (a | b << 6); // b0
                if (++i >= len) break;
                a = base64DecodeA(iter.next()); // b2[1..0] + b1[7..4]
                target[interleave[i]] = (byte) (a << 4 | b >> 2); // b1
                if (++i >= len) break;
                b = base64DecodeA(iter.next()); // b2[7..2]
                target[interleave[i]] = (byte) (b << 2 | a >> 4); // b2
            }
        } catch (NoSuchElementException ignored) {
            throw new InvalidKeySpecException("Unexpected end of input string");
        }
    }

    /**
     * Base-64 decode a sequence of characters into an appropriately-sized byte array at the given offset, using the
     * standard scheme and the modular crypt alphabet.
     *
     * @param iter the character iterator
     * @param target the target array
     */
    public static void base64DecodeA(CharacterArrayIterator iter, byte[] target) throws InvalidKeySpecException {
        int len = target.length;
        int a, b;
        try{
            for (int i = 0; i < len; ++i) {
                a = base64DecodeA(iter.next());
                b = base64DecodeA(iter.next());
                target[i] = (byte) (a << 2 | b >> 4);
                if (++i >= len) break;
                a = base64DecodeA(iter.next());
                target[i] = (byte) (b << 4 | a >> 2);
                if (++i >= len) break;
                b = base64DecodeA(iter.next());
                target[i] = (byte) (a << 6 | b >> 0);
            }
        } catch (NoSuchElementException ignored) {
            throw new InvalidKeySpecException("Unexpected end of input string");
        }
    }

    /**
     * Base-64 decode a sequence of characters into an appropriately-sized byte array at the given offset, using the
     * standard scheme and the standard alphabet.
     *
     * @param iter the character iterator
     * @param target the target array
     */
    public static void base64DecodeB(CharacterArrayIterator iter, byte[] target) throws InvalidKeySpecException {
        int len = target.length;
        int a, b;
        try{
            for (int i = 0; i < len; ++i) {
                a = base64DecodeB(iter.next());
                b = base64DecodeB(iter.next());
                target[i] = (byte) (a << 2 | b >> 4);
                if (++i >= len) break;
                a = base64DecodeB(iter.next());
                target[i] = (byte) (b << 4 | a >> 2);
                if (++i >= len) break;
                b = base64DecodeB(iter.next());
                target[i] = (byte) (a << 6 | b >> 0);
            }
        } catch (NoSuchElementException ignored) {
            throw new InvalidKeySpecException("Unexpected end of input string");
        }
    }

    /**
     * Base-64 decode a sequence of characters into an appropriately-sized byte array at the given offset, using the
     * standard scheme and the bcrypt alphabet.
     *
     * @param iter the character iterator
     * @param target the target array
     */
    public static void base64DecodeBCrypt(CharacterArrayIterator iter, byte[] target) throws InvalidKeySpecException {
        int len = target.length;
        int a, b;
        try{
            for (int i = 0; i < len; ++i) {
                a = base64DecodeBCrypt(iter.next());
                b = base64DecodeBCrypt(iter.next());
                target[i] = (byte) (a << 2 | b >> 4);
                if (++i >= len) break;
                a = base64DecodeBCrypt(iter.next());
                target[i] = (byte) (b << 4 | a >> 2);
                if (++i >= len) break;
                b = base64DecodeBCrypt(iter.next());
                target[i] = (byte) (a << 6 | b >> 0);
            }
        } catch (NoSuchElementException ignored) {
            throw new InvalidKeySpecException("Unexpected end of input string");
        }
    }

    /**
     * Base-64 decode a single character with alphabet A (DES/MD5/SHA crypt).
     *
     * @param ch the character
     * @return the byte
     * @throws InvalidKeySpecException if the character is not in the alphabet
     */
    public static int base64DecodeA(int ch) throws InvalidKeySpecException {
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

    /**
     * Base-64 decode a single character with the bcrypt alphabet.
     *
     * @param ch the character
     * @return the byte
     * @throws InvalidKeySpecException if the character is not in the alphabet
     */
    private static int base64DecodeBCrypt(int ch) throws InvalidKeySpecException {
        if (ch == '.') {
            return 0;
        } else if (ch == '/') {
            return 1;
        } else if (ch >= 'A' && ch <= 'Z') {
            return ch + 2 - 'A';
        } else if (ch >= 'a' && ch <= 'z') {
            return ch + 28 - 'a';
        } else if (ch >= '0' && ch <= '9') {
            return ch + 54 - '0';
        } else {
            throw new InvalidKeySpecException("Invalid character encountered");
        }
    }

    public static void base64EncodeA(StringBuilder target, ByteArrayIterator src) throws InvalidKeySpecException {
        int a, b;
        try{
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
        } catch (NoSuchElementException e) {
            throw new InvalidKeySpecException("Unexpected end of input bytes");
        }
    }

    public static void base64EncodeB(StringBuilder target, ByteArrayIterator src) throws InvalidKeySpecException {
        int a, b;
        try{
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
        } catch (NoSuchElementException e) {
            throw new InvalidKeySpecException("Unexpected end of input bytes");
        }
    }

    public static void base64EncodeBCrypt(StringBuilder target, ByteArrayIterator src) throws InvalidKeySpecException {
        int a, b;
        try{
            while (src.hasNext()) {
                a = src.next();
                base64EncodeBCrypt(target, a >> 2); // top 6 bits
                if (! src.hasNext()) {
                    base64EncodeBCrypt(target, a << 4); // bottom 2 bits + 0000
                    return;
                }
                b = src.next();
                base64EncodeBCrypt(target, (a & 0b11) << 4 | b >> 4); // bottom 2 bits + top 4 bits
                if (! src.hasNext()) {
                    base64EncodeBCrypt(target, b << 2); // bottom 4 bits + 00
                    return;
                }
                a = src.next();
                base64EncodeBCrypt(target, b << 2 | a >> 6); // bottom 4 bits + top 2 bits
                base64EncodeBCrypt(target, a); // bottom 6 bits
            }
        } catch (NoSuchElementException e) {
            throw new InvalidKeySpecException("Unexpected end of input bytes");
        }
    }

    public static void base64EncodeACryptLE(StringBuilder target, ByteArrayIterator src) throws InvalidKeySpecException {
        int a, b;
        try{
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
        } catch (NoSuchElementException e) {
            throw new InvalidKeySpecException("Unexpected end of input bytes");
        }
    }

    public static void base64EncodeA(StringBuilder target, int a) {
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

    public static void base64EncodeB(StringBuilder target, int a) {
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

    public static void base64EncodeBCrypt(StringBuilder target, int a) {
        a &= 0b0011_1111;
        final char c;
        if (a == 0) {
            c = '.';
        } else if (a == 1) {
            c = '/';
        } else if (a < 28) {
            c = (char) (a + 'A' - 2);
        } else if (a < 54) {
            c = (char) (a + 'a' - 28);
        } else { // a < 64
            c = (char) (a + '0' - 54);
        }
        target.append(c);
    }

}
