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

import java.util.NoSuchElementException;

/**
 * A code point by code point iterator.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public abstract class CodePointIterator {

    /**
     * Determine if there are more code points after the current code point.
     *
     * @return {@code true} if there are more code points, {@code false} otherwise
     */
    public abstract boolean hasNext();

    /**
     * Determine if there are more code points before the current code point.
     *
     * @return {@code true} if there are more code points, {@code false} otherwise
     */
    public abstract boolean hasPrev();

    /**
     * Determine if there is a current code point.  The current code point is updated after any call to
     * {@link #next()} or {@link #prev()}.
     *
     * @return {@code true} if there are more code points, {@code false} otherwise
     */
    public abstract boolean hasCurrent();

    /**
     * Get the next code point.
     *
     * @return the next code point
     * @throws NoSuchElementException if {@link #hasNext()} returns {@code false}
     */
    public abstract int next();

    /**
     * Get the previous code point.
     *
     * @return the previous code point
     * @throws NoSuchElementException if {@link #hasPrev()} returns {@code false}
     */
    public abstract int prev();

    /**
     * Get the current code point.
     *
     * @return the current code point
     * @throws NoSuchElementException if {@link #hasCurrent()} returns {@code false}
     */
    public abstract int current();

    /**
     * Get the current offset, by code point.
     *
     * @return the code point offset
     */
    public abstract int offset();

    /**
     * Get a code point iterator for a string.
     *
     * @param string the string
     * @return the code point iterator
     */
    public static CodePointIterator ofString(final String string) {
        final int length = string.length();
        return new CodePointIterator() {
            private int idx = 0;
            private int current = -1;
            private int offset = 0;

            public boolean hasNext() {
                return idx < length;
            }

            public boolean hasPrev() {
                return idx > 0;
            }

            public boolean hasCurrent() {
                return current != -1;
            }

            public int next() {
                if (! hasNext()) throw new NoSuchElementException();
                try {
                    offset++;
                    return current = string.codePointAt(idx);
                } finally {
                    idx = string.offsetByCodePoints(idx, 1);
                }
            }

            public int prev() {
                if (! hasPrev()) throw new NoSuchElementException();
                idx = string.offsetByCodePoints(idx, -1);
                offset--;
                return current = string.codePointAt(idx);
            }

            public int current() {
                if (! hasCurrent()) throw new NoSuchElementException();
                return current;
            }

            public int offset() {
                return offset;
            }
        };
    }

    /**
     * Get a code point iterator for a character array.
     *
     * @param chars the array
     * @return the code point iterator
     */
    public static CodePointIterator ofChars(final char[] chars) {
        return ofChars(chars, 0, chars.length);
    }

    /**
     * Get a code point iterator for a character array.
     *
     * @param chars the array
     * @param offs the array offset
     * @param len the number of characters to include
     * @return the code point iterator
     */
    public static CodePointIterator ofChars(final char[] chars, final int offs, final int len) {
        return new CodePointIterator() {
            private int idx = 0;
            private int current = -1;
            private int offset = 0;

            public boolean hasNext() {
                return idx < len;
            }

            public boolean hasPrev() {
                return idx > 0;
            }

            public boolean hasCurrent() {
                return current != -1;
            }

            public int next() {
                if (! hasNext()) throw new NoSuchElementException();
                try {
                    offset++;
                    return current = Character.codePointAt(chars, offs + idx);
                } finally {
                    idx = Character.offsetByCodePoints(chars, offs, len, idx, 1);
                }
            }

            public int prev() {
                if (! hasPrev()) throw new NoSuchElementException();
                idx = Character.offsetByCodePoints(chars, offs, len, idx, -1);
                offset--;
                return current = Character.codePointAt(chars, offs + idx);
            }

            public int current() {
                if (! hasCurrent()) throw new NoSuchElementException();
                return current;
            }

            public int offset() {
                return offset;
            }
        };
    }

    /**
     * Get a code point iterator for a UTF-8 encoded byte array.
     *
     * @param bytes the array
     * @return the code point iterator
     */
    public static CodePointIterator ofUtf8Bytes(final byte[] bytes) {
        return ofUtf8Bytes(bytes, 0, bytes.length);
    }

    /**
     * Get a code point iterator for a UTF-8 encoded array.
     *
     * @param bytes the array
     * @param offs the array offset
     * @param len the number of characters to include
     * @return the code point iterator
     */
    public static CodePointIterator ofUtf8Bytes(final byte[] bytes, final int offs, final int len) {
        return new CodePointIterator() {
            private int idx = 0;
            private int current = -1;
            private int offset = 0;

            public boolean hasNext() {
                return idx < len;
            }

            public boolean hasPrev() {
                return idx > 0;
            }

            public boolean hasCurrent() {
                return current != -1;
            }

            private void seekToNext() {
                int b;
                while (idx < len) {
                    b = bytes[offs + idx];
                    if ((b & 0b11_000000) != 0b10_000000) {
                        return;
                    }
                    idx ++;
                }
            }

            private void seekToPrev() {
                int b;
                while (--idx > 0) {
                    b = bytes[offs + idx];
                    if ((b & 0b11_000000) != 0b10_000000) {
                        return;
                    }
                }
            }

            public int next() {
                if (! hasNext()) throw new NoSuchElementException();
                offset++;
                // >= 1 byte
                int a = bytes[offs + idx++];
                if ((a & 0b1_0000000) == 0b0_0000000) {
                    // one byte
                    return current = a;
                }
                if ((a & 0b11_000000) == 0b10_000000) {
                    // first byte is invalid; return � instead
                    seekToNext();
                    return current = '�';
                }
                // >= 2 bytes
                if (idx == len) {
                    // truncated
                    return current = '�';
                }
                int b = bytes[offs + idx++];
                if ((b & 0b11_000000) != 0b10_000000) {
                    // second byte is invalid; return � instead
                    seekToNext();
                    return current = '�';
                }
                if ((a & 0b111_00000) == 0b110_00000) {
                    // two bytes
                    return current = a & 0b000_11111 << 6 | b & 0b00_111111;
                }
                // >= 3 bytes
                if (idx == len) {
                    // truncated
                    return current = '�';
                }
                int c = bytes[offs + idx++];
                if ((c & 0b11_000000) != 0b10_000000) {
                    // third byte is invalid; return � instead
                    seekToNext();
                    return current = '�';
                }
                if ((a & 0b1111_0000) == 0b1110_0000) {
                    // three bytes
                    return current = a & 0b0000_1111 << 12 | b & 0b00_111111 << 6 | c & 0b00_111111;
                }
                // >= 4 bytes
                if (idx == len) {
                    // truncated
                    return current = '�';
                }
                int d = bytes[offs + idx++];
                if ((d & 0b11_000000) != 0b10_000000) {
                    // fourth byte is invalid; return � instead
                    seekToNext();
                    return current = '�';
                }
                if ((a & 0b11111_000) == 0b11110_000) {
                    // four bytes
                    return current = a & 0b00000_111 << 18 | b & 0b00_111111 << 12 | c & 0b00_111111 << 6 | d & 0b00_111111;
                }
                // only invalid possibilities are left; return � instead
                seekToNext();
                return current = '�';
            }

            public int prev() {
                if (! hasPrev()) throw new NoSuchElementException();
                offset--;
                seekToPrev();
                // >= 1 byte
                int a = bytes[offs + idx];
                if ((a & 0b1_0000000) == 0b0_0000000) {
                    // one byte
                    return current = a;
                }
                if ((a & 0b11_000000) == 0b10_000000) {
                    // first byte is invalid; return � instead
                    return current = '�';
                }
                // >= 2 bytes
                if (idx + 1 == len) {
                    // truncated
                    return current = '�';
                }
                int b = bytes[offs + idx + 1];
                if ((b & 0b11_000000) != 0b10_000000) {
                    // second byte is invalid; return � instead
                    return current = '�';
                }
                if ((a & 0b111_00000) == 0b110_00000) {
                    // two bytes
                    return current = a & 0b000_11111 << 6 | b & 0b00_111111;
                }
                // >= 3 bytes
                if (idx + 2 == len) {
                    // truncated
                    return current = '�';
                }
                int c = bytes[offs + idx + 2];
                if ((c & 0b11_000000) != 0b10_000000) {
                    // third byte is invalid; return � instead
                    return current = '�';
                }
                if ((a & 0b1111_0000) == 0b1110_0000) {
                    // three bytes
                    return current = a & 0b0000_1111 << 12 | b & 0b00_111111 << 6 | c & 0b00_111111;
                }
                // >= 4 bytes
                if (idx + 3 == len) {
                    // truncated
                    return current = '�';
                }
                int d = bytes[offs + idx + 3];
                if ((d & 0b11_000000) != 0b10_000000) {
                    // fourth byte is invalid; return � instead
                    return current = '�';
                }
                if ((a & 0b11111_000) == 0b11110_000) {
                    // four bytes
                    return current = a & 0b00000_111 << 18 | b & 0b00_111111 << 12 | c & 0b00_111111 << 6 | d & 0b00_111111;
                }
                // only invalid possibilities are left; return � instead
                return current = '�';
            }

            public int current() {
                if (! hasCurrent()) throw new NoSuchElementException();
                return current;
            }

            public int offset() {
                return offset;
            }
        };
    }

    /**
     * Get a code point iterator for a ISO-8859-1 (Latin-1) encoded array.
     *
     * @param bytes the array
     * @return the code point iterator
     */
    public static CodePointIterator ofLatin1Bytes(final byte[] bytes) {
        return ofLatin1Bytes(bytes, 0, bytes.length);
    }

    /**
     * Get a code point iterator for a ISO-8859-1 (Latin-1) encoded array.
     *
     * @param bytes the array
     * @param offs the array offset
     * @param len the number of characters to include
     * @return the code point iterator
     */
    public static CodePointIterator ofLatin1Bytes(final byte[] bytes, final int offs, final int len) {
        return new CodePointIterator() {
            int idx = 0;
            int current = -1;

            public boolean hasNext() {
                return idx < len;
            }

            public boolean hasPrev() {
                return idx > 0;
            }

            public boolean hasCurrent() {
                return current != -1;
            }

            public int next() {
                if (! hasNext()) throw new NoSuchElementException();
                return current = bytes[offs + idx++];
            }

            public int prev() {
                if (! hasPrev()) throw new NoSuchElementException();
                return current = bytes[offs + --idx];
            }

            public int current() {
                if (! hasCurrent()) throw new NoSuchElementException();
                return current;
            }

            public int offset() {
                return idx;
            }
        };
    }
}
