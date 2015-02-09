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

package org.wildfly.security.sasl.scram;

import java.security.InvalidKeyException;
import java.util.Random;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.wildfly.security.sasl.util.StringPrep;
import org.wildfly.security.util.ByteIterator;
import org.wildfly.security.util.ByteStringBuilder;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
class ScramUtil {
    private static final byte[] randomCharDictionary;

    static {
        byte[] dict = new byte[93];
        int i = 0;
        for (byte c = '!'; c < ','; c ++) {
            dict[i ++] = c;
        }
        for (byte c = ',' + 1; c < 127; c ++) {
            dict[i ++] = c;
        }
        assert i == dict.length;
        randomCharDictionary = dict;
    }

    public static void generateRandomString(StringBuilder b, int length, Random random) {
        for (int i = 0; i < length; i ++) {
            b.append(randomCharDictionary[random.nextInt(93)]);
        }
    }

    public static byte[] generateRandomString(int length, Random random) {
        final byte[] chars = new byte[length];
        for (int i = 0; i < length; i ++) {
            chars[i] = randomCharDictionary[random.nextInt(93)];
        }
        return chars;
    }

    public static int parsePosInt(final ByteIterator i) {
        int a, c;
        if (! i.hasNext()) {
            throw new NumberFormatException("Empty number");
        }
        c = i.next();
        if (c >= '1' && c <= '9') {
            a = c - '0';
        } else {
            throw new NumberFormatException("Invalid numeric character");
        }
        while (i.hasNext()) {
            c = i.next();
            if (c >= '0' && c <= '9') {
                a = (a << 3) + (a << 1) + (c - '0');
                if (a < 0) {
                    throw new NumberFormatException("Too big");
                }
            } else {
                throw new NumberFormatException("Invalid numeric character");
            }
        }
        return a;
    }

    public static int parsePosInt(byte[] src, int offset, int len) {
        int count = 1;
        int a, c;
        if (len == 0) {
            throw new NumberFormatException("Empty number");
        }
        c = src[offset];
        if (c == ',') {
            throw new NumberFormatException("Empty number");
        }
        if (c >= '1' && c <= '9') {
            a = c - '0';
        } else {
            throw new NumberFormatException("Invalid numeric character");
        }
        do {
            c = src[offset + count++];
            if (c >= '0' && c <= '9') {
                a = (a << 3) + (a << 1) + (c - '0');
                if (a < 0) {
                    throw new NumberFormatException("Too big");
                }
            } else if (c == ',') {
                return a;
            } else {
                throw new NumberFormatException("Invalid numeric character");
            }
        } while (count < len);
        return a;
    }

    public static int parsePosInt(byte[] src, int offset) {
        return parsePosInt(src, offset, src.length - offset);
    }

    public static int parseString(byte[] src, int offset, int terminator, StringBuilder b) {
        int count = 0;
        int c, d;
        try {
            c = src[offset + count++] & 0xff;
            for (;;) {
                if (c < 0x80) {
                    if (c == terminator) {
                        return count;
                    }
                    b.append((char) c);
                } else if (c >= 0xC0 && c < 0xE0) {
                    // 2 byte seq
                    c <<= 6;
                    d = src[offset + count++] & 0xff;
                    if (d < 0x80 || d >= 0xC0) {
                        b.appendCodePoint(0xFFFC);
                        continue;
                    }
                    c |= d & 0x3F;
                    if (c == terminator) {
                        return count;
                    }
                    b.appendCodePoint(c);
                } else if (c >= 0xE0 && c < 0xF0) {
                    // 3 byte seq
                    c <<= 12;
                    d = src[offset + count++] & 0xff;
                    if (d < 0x80 || d >= 0xC0) {
                        b.appendCodePoint(0xFFFC);
                        continue;
                    }
                    c |= (d & 0x3F) << 6;
                    d = src[offset + count++] & 0xff;
                    if (d < 0x80 || d >= 0xC0) {
                        b.appendCodePoint(0xFFFC);
                        continue;
                    }
                    c |= d & 0x3F;
                    if (c == terminator) {
                        return count;
                    }
                    b.appendCodePoint(c);
                } else if (c >= 0xF0 && c < 0xF8) {
                    // 4 byte seq
                    c <<= 18;
                    d = src[offset + count++] & 0xff;
                    if (d < 0x80 || d >= 0xC0) {
                        b.appendCodePoint(0xFFFC);
                        continue;
                    }
                    c |= (d & 0x3F) << 12;
                    d = src[offset + count++] & 0xff;
                    if (d < 0x80 || d >= 0xC0) {
                        b.appendCodePoint(0xFFFC);
                        continue;
                    }
                    c |= (d & 0x3F) << 6;
                    d = src[offset + count++] & 0xff;
                    if (d < 0x80 || d >= 0xC0) {
                        b.appendCodePoint(0xFFFC);
                        continue;
                    }
                    c |= d & 0x3F;
                    if (c == terminator) {
                        return count;
                    }
                    b.appendCodePoint(c);
                } else {
                    b.appendCodePoint(0xFFFC); // replacement char
                }
                c = src[offset + count++] & 0xff;
            }
        } catch (ArrayIndexOutOfBoundsException ignored) {}
        return count;
    }

    public static int decimalDigitCount(int num) {
        if (num < 10) return 1;
        if (num < 100) return 2;
        if (num < 1000) return 3;
        if (num < 10000) return 4;
        if (num < 100000) return 5;
        if (num < 1000000) return 6;
        if (num < 10000000) return 7;
        if (num < 100000000) return 8;
        if (num < 1000000000) return 9;
        return 10;
    }

    public static byte[] calculateHi(Mac mac, char[] password, byte[] salt, int saltOffs, int saltLen, int iterationCount) throws InvalidKeyException {
        try {
            final ByteStringBuilder b = new ByteStringBuilder();
            StringPrep.encode(password, b, StringPrep.PROFILE_SASL_QUERY);
            mac.init(new SecretKeySpec(b.toArray(), mac.getAlgorithm()));
            mac.update(salt, saltOffs, saltLen);
            mac.update((byte) 1);
            mac.update((byte) 0);
            mac.update((byte) 0);
            mac.update((byte) 0);
            byte[] h = mac.doFinal();
            byte[] u = h;
            for (int i = 2; i <= iterationCount; i ++) {
                u = mac.doFinal(u);
                xor(h, u);
            }
            return h;
        } finally {
            mac.reset();
        }
    }

    public static void xor(byte[] key, byte val) {
        for (int i = 0; i < key.length; i++) {
            key[i] ^= val;
        }
    }

    public static void xor(final byte[] hash, final byte[] input) {
        assert hash.length == input.length;
        for (int i = 0; i < hash.length; i++) {
            hash[i] ^= input[i];
        }
    }

    public static void xor(final byte[] hash, final byte[] input, final int offs, final int len) {
        assert hash.length == len;
        for (int i = 0; i < hash.length; i ++) {
            hash[i] ^= input[i + offs];
        }
    }
}
