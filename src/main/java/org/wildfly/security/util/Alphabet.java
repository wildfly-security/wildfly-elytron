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
 * An alphabet.
 *
 * @deprecated
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
@Deprecated
public abstract class Alphabet {
    final boolean littleEndian;

    Alphabet(final boolean littleEndian) {
        this.littleEndian = littleEndian;
    }

    /**
     * Encode the given value to a code point.
     *
     * @param val the value
     * @return the code point
     */
    public abstract int encode(int val);

    /**
     * Decode the given code point.  If the code point is not valid, -1 is returned.
     *
     * @param codePoint the code point
     * @return the decoded value or -1
     */
    public abstract int decode(int codePoint);

    /**
     * A base-64 alphabet.
     *
     * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
     */
    public abstract static class Base64Alphabet extends Alphabet {

        Base64Alphabet(final boolean littleEndian) {
            super(littleEndian);
        }

        /**
         * Encode the given 6-bit value to a code point.
         *
         * @param val the 6-bit value
         * @return the code point
         */
        public abstract int encode(int val);

        /**
         * Decode the given code point.  If the code point is not valid, -1 is returned.
         *
         * @param codePoint the code point
         * @return the decoded 6-bit value or -1
         */
        public abstract int decode(int codePoint);

        /**
         * The standard <a href="http://tools.ietf.org/html/rfc4648">RFC 4648</a> base-64 alphabet.
         */
        public static final Base64Alphabet STANDARD = new Base64Alphabet(false) {
            public int encode(final int val) {
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

            public int decode(final int codePoint) throws IllegalArgumentException {
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
        public static final Base64Alphabet MOD_CRYPT = new Base64Alphabet(false) {
            public int encode(final int val) {
                if (val == 0) {
                    return '.';
                } else if (val == 1) {
                    return '/';
                } else if (val <= 11) {
                    return '0' + val - 2;
                } else if (val <= 37) {
                    return 'A' + val - 12;
                } else {
                    assert val < 64;
                    return 'a' + val - 38;
                }
            }

            public int decode(final int codePoint) throws IllegalArgumentException {
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
         * The modular crypt alphabet, used in various modular crypt password types.
         */
        public static final Base64Alphabet MOD_CRYPT_LE = new Base64Alphabet(true) {
            public int encode(final int val) {
                if (val == 0) {
                    return '.';
                } else if (val == 1) {
                    return '/';
                } else if (val <= 11) {
                    return '0' + val - 2;
                } else if (val <= 37) {
                    return 'A' + val - 12;
                } else {
                    assert val < 64;
                    return 'a' + val - 38;
                }
            }

            public int decode(final int codePoint) throws IllegalArgumentException {
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
        public static final Base64Alphabet BCRYPT = new Base64Alphabet(false) {
            public int encode(final int val) {
                if (val == 0) {
                    return '.';
                } else if (val == 1) {
                    return '/';
                } else if (val <= 27) {
                    return 'A' + val - 2;
                } else if (val <= 53) {
                    return 'a' + val - 28;
                } else {
                    assert val < 64;
                    return '0' + val - 54;
                }
            }

            public int decode(final int codePoint) {
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

    /**
     * A base-32 alphabet.
     *
     * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
     */
    public abstract static class Base32Alphabet extends Alphabet {

        Base32Alphabet(final boolean littleEndian) {
            super(littleEndian);
        }

        /**
         * Encode the given 5-bit value to a code point.
         *
         * @param val the 5-bit value
         * @return the code point
         */
        public abstract int encode(int val);

        /**
         * Decode the given code point.  If the code point is not valid, -1 is returned.
         *
         * @param codePoint the code point
         * @return the decoded 5-bit value or -1
         */
        public abstract int decode(int codePoint);

        /**
         * The standard <a href="http://tools.ietf.org/html/rfc4648">RFC 4648</a> base-32 alphabet.
         */
        public static final Base32Alphabet STANDARD = new Base32Alphabet(false) {
            public int encode(final int val) {
                if (val <= 25) {
                    return 'A' + val;
                } else {
                    assert val < 32;
                    return '2' + val - 26;
                }
            }

            public int decode(final int codePoint) {
                if ('A' <= codePoint && codePoint <= 'Z') {
                    return codePoint - 'A';
                } else if ('2' <= codePoint && codePoint <= '7') {
                    return codePoint - '2' + 26;
                } else {
                    return -1;
                }
            }
        };

        /**
         * The standard <a href="http://tools.ietf.org/html/rfc4648">RFC 4648</a> base-32 alphabet mapped to lowercase.
         */
        public static final Base32Alphabet LOWERCASE = new Base32Alphabet(false) {
            public int encode(final int val) {
                if (val <= 25) {
                    return 'a' + val;
                } else {
                    assert val < 32;
                    return '2' + val - 26;
                }
            }

            public int decode(final int codePoint) {
                if ('a' <= codePoint && codePoint <= 'z') {
                    return codePoint - 'a';
                } else if ('2' <= codePoint && codePoint <= '7') {
                    return codePoint - '2' + 26;
                } else {
                    return -1;
                }
            }
        };

    }
    /**
     * The alphabet used by PicketBox project base 64 encoding.
     * {@code 0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz./}
     */
    public static final Base64Alphabet PICKETBOX_COMPATIBILITY = new Base64Alphabet(false) {
        public int encode(int val) {
            if (val <= 9) {
                return '0' + val;
            } else if (val <= 35) {
                return 'A' + val - 10;
            } else if (val <= 61) {
                return 'a' + val - 36;
            } else if (val == 62) {
                return '.';
            } else {
                assert val == 63;
                return '/';
            }
        }

        public int decode(int codePoint) {
            if ('0' <= codePoint && codePoint <= '9') {
                return codePoint - '0';
            } else if ('A' <= codePoint && codePoint <= 'Z') {
                return codePoint - 'A' + 10;
            } else if ('a' <= codePoint && codePoint <= 'z') {
                return codePoint - 'a' + 36;
            } else if (codePoint == '.') {
                return 62;
            } else if (codePoint == '/') {
                return 63;
            } else {
                return -1;
            }
        }
    };

}
