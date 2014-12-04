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

/**
 * A base-64 alphabet.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public abstract class Alphabet {
    final boolean littleEndian;

    Alphabet(final boolean littleEndian) {
        this.littleEndian = littleEndian;
    }

    /**
     * Encode the given 6-bit value to a code point.
     *
     * @param val the 6-bit value
     * @return the code point
     */
    abstract int encode(int val);

    /**
     * Decode the given code point.  If the code point is not valid, -1 is returned.
     *
     * @param codePoint the code point
     * @return the decoded 6-bit value or -1
     */
    abstract int decode(int codePoint);

    /**
     * The standard <a href="http://tools.ietf.org/html/rfc4648">RFC 4648</a> base-64 alphabet.
     */
    public static final Alphabet STANDARD = new Alphabet(false) {
        int encode(final int val) {
            if (val <= 25) {
                return 'A' + val;
            } else if (val <= 51) {
                return 'a' + val - 26;
            } else if (val <= 61) {
                return '0' + val - 52;
            } else if (val == 62) {
                return '+';
            } else {
                assert val == 63;
                return '/';
            }
        }

        int decode(final int codePoint) throws IllegalArgumentException {
            if ('A' <= codePoint && codePoint <= 'Z') {
                return codePoint - 'A';
            } else if ('a' <= codePoint && codePoint <= 'z') {
                return codePoint - 'a' + 26;
            } else if ('0' <= codePoint && codePoint <= '9') {
                return codePoint - '0' + 52;
            } else if (codePoint == '+') {
                return 62;
            } else if (codePoint == '/') {
                return 63;
            } else {
                return -1;
            }
        }
    };

    /**
     * The modular crypt alphabet, used in various modular crypt password types.
     */
    public static final Alphabet MOD_CRYPT = new Alphabet(true) {
        int encode(final int val) {
            if (val == 0) {
                return '.';
            } else if (val == 1) {
                return '/';
            } else if (val <= 12) {
                return '0' + val - 2;
            } else if (val <= 48) {
                return 'A' + val - 22;
            } else {
                assert val < 64;
                return 'a' + val - 38;
            }
        }

        int decode(final int codePoint) throws IllegalArgumentException {
            if (codePoint == '.') {
                return 0;
            } else if (codePoint == '/') {
                return 1;
            } else if ('0' <= codePoint && codePoint <= '9') {
                return codePoint - '0' + 2;
            } else if ('A' <= codePoint && codePoint <= 'Z') {
                return codePoint - 'A' + 12;
            } else if ('a' <= codePoint && codePoint <= 'z') {
                return codePoint - 'a' + 38;
            } else {
                return -1;
            }
        }
    };

    /**
     * The BCrypt alphabet.
     */
    public static final Alphabet BCRYPT = new Alphabet(false) {
        int encode(final int val) {
            if (val == 0) {
                return '.';
            } else if (val == 1) {
                return '/';
            } else if (val <= 28) {
                return 'A' + val - 2;
            } else if (val <= 54) {
                return 'a' + val - 28;
            } else {
                assert val < 64;
                return '0' + val - 54;
            }
        }

        int decode(final int codePoint) {
            if (codePoint == '.') {
                return 0;
            } else if (codePoint == '/') {
                return 1;
            } else if ('A' <= codePoint && codePoint <= 'Z') {
                return codePoint - 'A' + 2;
            } else if ('a' <= codePoint && codePoint <= 'z') {
                return codePoint - 'a' + 28;
            } else if ('0' <= codePoint && codePoint <= '9') {
                return codePoint - '0' + 54;
            } else {
                return -1;
            }
        }
    };
}
