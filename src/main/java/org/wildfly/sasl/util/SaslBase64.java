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

package org.wildfly.sasl.util;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class SaslBase64 {

    private static final byte[] alphabet = {
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
        'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
        'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
        'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
        'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
        'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
        'w', 'x', 'y', 'z', '0', '1', '2', '3',
        '4', '5', '6', '7', '8', '9', '+', '/'
    };

    public static void encode(byte[] original, int offset, int len, ByteStringBuilder target) {
        final byte[] alphabet = SaslBase64.alphabet;
        int count = 0;
        byte s;
        while (count < len) {
            s = original[offset + count++];
            // first the top 6 bits of the first byte
            target.appendNumber(alphabet[s >>> 2]);
            if (count == len) {
                // bottom 2 bits + 4 zero bits
                target.appendNumber(alphabet[s << 4 & 0x3f]).append('=').append('=');
                return;
            }
            // bottom 2 bits + top 4 bits of second byte
            target.appendNumber(alphabet[(s << 4 | (s = original[offset + count++]) >>> 4) & 0x3f]);
            if (count == len) {
                // bottom 4 bits + 2 zero bits
                target.appendNumber(alphabet[s << 2 & 0x3f]).append('=');
                return;
            }
            // bottom 4 bits + top 2 bits of third byte
            target.appendNumber(alphabet[(s << 2 | (s = original[offset + count++]) >>> 6) & 0x3f]);
            // bottom 6 bits of third byte
            target.appendNumber(alphabet[s & 0x3f]);
        }
        // ended right on a boundary, handy
    }

    public static void encode(byte[] original, ByteStringBuilder target) {
        encode(original, 0, original.length, target);
    }

    private static int decodeByte(byte b) {
        if (b >= 'A' && b <= 'Z') {
            return b - 'A';
        } else if (b >= 'a' && b <= 'z') {
            return b - 'a' + 26;
        } else if (b >= '0' && b <= '9') {
            return b - '0' + 52;
        } else if (b == '+') {
            return 62;
        } else if (b == '/') {
            return 63;
        } else if (b == '=') {
            return -2;
        } else {
            return -1;
        }
    }

    public static int decode(byte[] encoded, int offset, int len, ByteStringBuilder target) throws IllegalArgumentException {
        int count = 0;
        int t1, t2;
        while (count < len) {
            // top 6 bits of the first byte
            t1 = decodeByte(encoded[offset + count++]);
            if (t1 == -1) return count - 1;
            if (t1 == -2) throw unexpectedPadding();
            if (count == len) throw truncatedInput();

            // bottom 2 bits + top 4 bits of the second byte
            t2 = decodeByte(encoded[offset + count++]);
            if (t2 == -1) throw truncatedInput();
            if (t2 == -2) throw unexpectedPadding();
            if (count == len) throw truncatedInput();
            target.appendNumber((byte) (t1 << 2 | t2 >>> 4));

            // bottom 4 bits + top 2 bits of the third byte - or == if it's the end
            t1 = decodeByte(encoded[offset + count++]);
            if (t1 == -1) throw truncatedInput();
            if (count == len) throw truncatedInput();
            if (t1 == -2) {
                // expect one more byte of padding
                assert count < len;
                if (encoded[offset + count++] != '=') {
                    throw missingRequiredPadding();
                }
                return count;
            }
            target.appendNumber((byte) (t2 << 4 | t1 >>> 4));

            // bottom 6 bits of the third byte - or = if it's the end
            t2 = decodeByte(encoded[offset + count++]);
            if (t2 == -1) throw truncatedInput();
            if (t2 == -2) return count;
            target.appendNumber((byte) (t1 << 6 | t2));
        }
        return count;
    }

    public static int decode(byte[] encoded, int offset, ByteStringBuilder target) throws IllegalArgumentException {
        return decode(encoded, offset, encoded.length - offset, target);
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
