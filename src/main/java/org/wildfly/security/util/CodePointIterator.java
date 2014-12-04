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
public abstract class CodePointIterator extends NumericIterator {

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
     * Get the next code point.
     *
     * @return the next code point
     * @throws NoSuchElementException if {@link #hasNext()} returns {@code false}
     */
    public abstract int next() throws NoSuchElementException;

    /**
     * Peek at the next code point without advancing.
     *
     * @return the next code point
     * @throws NoSuchElementException if {@link #hasNext()} returns {@code false}
     */
    public abstract int peekNext() throws NoSuchElementException;

    /**
     * Get the previous code point.
     *
     * @return the previous code point
     * @throws NoSuchElementException if {@link #hasPrev()} returns {@code false}
     */
    public abstract int prev() throws NoSuchElementException;

    /**
     * Peek at the previous code point without moving backwards.
     *
     * @return the previous code point
     * @throws NoSuchElementException if {@link #hasPrev()} returns {@code false}
     */
    public abstract int peekPrev() throws NoSuchElementException;

    /**
     * Get the current offset, by code point.
     *
     * @return the code point offset
     */
    public abstract int offset();

    /**
     * Determine if the remaining contents of this iterator are identical to the remaining contents of the other iterator.  If the
     * contents are not equal, the iterators will be positioned at the location of the first difference.  If the contents
     * are equal, the iterators will both be positioned at the end of their contents.
     *
     * @param other the other byte iterator
     * @return {@code true} if the contents are equal, {@code false} otherwise
     */
    public final boolean contentEquals(CodePointIterator other) {
        for (;;) {
            if (hasNext()) {
                if (! other.hasNext()) {
                    return false;
                }
                if (next() != other.next()) {
                    return false;
                }
            } else {
                return ! other.hasNext();
            }
        }
    }

    /**
     * Return a copy of this iterator which is limited to the given number of code points after the current one.  Advancing
     * the returned iterator will also advance this one.
     *
     * @param size the number of code points
     * @return the limited code point iterator
     */
    public final CodePointIterator limitedTo(final int size) {
        if (size <= 0 || ! hasNext()) {
            return EMPTY;
        }
        return new CodePointIterator() {
            int offset = 0;

            public boolean hasNext() {
                return offset < size && CodePointIterator.this.hasNext();
            }

            public boolean hasPrev() {
                return offset > 0;
            }

            public int next() {
                if (! hasNext()) {
                    throw new NoSuchElementException();
                }
                offset ++;
                return CodePointIterator.this.next();
            }

            public int peekNext() throws NoSuchElementException {
                if (! hasNext()) {
                    throw new NoSuchElementException();
                }
                return CodePointIterator.this.peekNext();
            }

            public int prev() {
                if (! hasPrev()) {
                    throw new NoSuchElementException();
                }
                offset --;
                return CodePointIterator.this.prev();
            }

            public int peekPrev() throws NoSuchElementException {
                if (! hasPrev()) {
                    throw new NoSuchElementException();
                }
                return CodePointIterator.this.peekPrev();
            }

            public int offset() {
                return offset;
            }
        };
    }

    /**
     * Get a sub-iterator that is delimited by the given code point.  The returned iterator offset starts at 0 and cannot
     * be backed up before that point.  The returned iterator will return {@code false} for {@code hasNext()} if the next
     * character in the encapsulated iterator is a delimiter or if the underlying iterator returns {@code false} for
     * {@code hasNext()}.
     *
     * @param delim the code point delimiter
     * @return the sub-iterator
     */
    public final CodePointIterator delimitedBy(final int delim) {
        if (! Character.isValidCodePoint(delim) || ! hasNext()) {
            return EMPTY;
        }
        return new CodePointIterator() {
            int offset = 0;

            public boolean hasNext() {
                return CodePointIterator.this.hasNext() && CodePointIterator.this.peekNext() != delim;
            }

            public boolean hasPrev() {
                return offset > 0;
            }

            public int next() {
                if (! hasNext()) {
                    throw new NoSuchElementException();
                }
                offset ++;
                return CodePointIterator.this.next();
            }

            public int peekNext() throws NoSuchElementException {
                if (! hasNext()) {
                    throw new NoSuchElementException();
                }
                return CodePointIterator.this.peekNext();
            }

            public int prev() {
                if (! hasPrev()) {
                    throw new NoSuchElementException();
                }
                offset --;
                return CodePointIterator.this.prev();
            }

            public int peekPrev() throws NoSuchElementException {
                if (! hasPrev()) {
                    throw new NoSuchElementException();
                }
                return CodePointIterator.this.peekPrev();
            }

            public int offset() {
                return offset;
            }
        };
    }

    /**
     * Drain all the remaining code points in this iterator to the given string builder.
     *
     * @param b the string builder
     * @return the same string builder
     */
    public StringBuilder drainTo(StringBuilder b) {
        while (hasNext()) {
            b.appendCodePoint(next());
        }
        return b;
    }

    /**
     * Drain all the remaining code points in this iterator to a new string.
     *
     * @return the string
     */
    public String drainToString() {
        return hasNext() ? drainTo(new StringBuilder()).toString() : "";
    }

    /**
     * Base64-decode the current stream.
     *
     * @param alphabet the alphabet to use
     * @param requirePadding {@code true} to require padding, {@code false} if padding is optional
     * @return an iterator over the decoded bytes
     */
    public ByteIterator base64Decode(final Alphabet alphabet, boolean requirePadding) {
        return super.base64Decode(alphabet, requirePadding);
    }

    /**
     * Base64-decode the current stream.
     *
     * @param alphabet the alphabet to use
     * @return an iterator over the decoded bytes
     */
    public ByteIterator base64Decode(final Alphabet alphabet) {
        return super.base64Decode(alphabet, true);
    }

    /**
     * Base64-decode the current stream.
     *
     * @return an iterator over the decoded bytes
     */
    public ByteIterator base64Decode() {
        return super.base64Decode(Alphabet.STANDARD, true);
    }

    /**
     * Get a code point iterator for a string.
     *
     * @param string the string
     * @return the code point iterator
     */
    public static CodePointIterator ofString(final String string) {
        return ofString(string, 0, string.length());
    }

    /**
     * Get a code point iterator for a string.
     *
     * @param string the string
     * @return the code point iterator
     */
    public static CodePointIterator ofString(final String string, final int offs, final int len) {
        if (len == 0) {
            return EMPTY;
        }
        return new CodePointIterator() {
            private int idx = 0;
            private int current = -1;
            private int offset = 0;

            public boolean hasNext() {
                return idx < len;
            }

            public boolean hasPrev() {
                return offset > 0;
            }

            public int next() {
                if (! hasNext()) throw new NoSuchElementException();
                try {
                    offset++;
                    return current = string.codePointAt(idx + offs);
                } finally {
                    idx = string.offsetByCodePoints(idx + offs, 1) - offs;
                }
            }

            public int peekNext() throws NoSuchElementException {
                if (! hasNext()) throw new NoSuchElementException();
                return string.codePointAt(idx + offs);
            }

            public int prev() {
                if (! hasPrev()) throw new NoSuchElementException();
                idx = string.offsetByCodePoints(idx + offs, -1) - offs;
                offset--;
                return current = string.codePointAt(idx + offs);
            }

            public int peekPrev() throws NoSuchElementException {
                if (! hasPrev()) throw new NoSuchElementException();
                return string.codePointBefore(idx + offs);
            }

            public int offset() {
                return offset;
            }

            public StringBuilder drainTo(final StringBuilder b) {
                try {
                    return b.append(string, idx + offs, offs + len);
                } finally {
                    offset += string.codePointCount(idx + offs, offs + len);
                    idx = len;
                }
            }

            public String drainToString() {
                try {
                    return string.substring(idx + offs, offs + len);
                } finally {
                    offset += string.codePointCount(idx + offs, offs + len);
                    idx = len;
                }
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
        if (len <= 0) {
            return EMPTY;
        }
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

            public int next() {
                if (! hasNext()) throw new NoSuchElementException();
                try {
                    offset++;
                    return current = Character.codePointAt(chars, offs + idx);
                } finally {
                    idx = Character.offsetByCodePoints(chars, offs, len, idx, 1);
                }
            }

            public int peekNext() throws NoSuchElementException {
                if (! hasNext()) throw new NoSuchElementException();
                return Character.codePointAt(chars, offs + idx);
            }

            public int prev() {
                if (! hasPrev()) throw new NoSuchElementException();
                idx = Character.offsetByCodePoints(chars, offs, len, idx, -1);
                offset--;
                return current = Character.codePointAt(chars, offs + idx);
            }

            public int peekPrev() throws NoSuchElementException {
                if (! hasPrev()) throw new NoSuchElementException();
                return Character.codePointBefore(chars, offs + idx);
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
        if (len <= 0) {
            return EMPTY;
        }
        return ofUtf8Bytes(ByteIterator.ofBytes(bytes, offs, len));
    }

    /**
     * Get a code point iterator for a UTF-8 encoded byte iterator.
     *
     * @param iterator the byte iterator
     * @return the code point iterator
     */
    public static CodePointIterator ofUtf8Bytes(final ByteIterator iterator) {
        if (! iterator.hasNext()) {
            return EMPTY;
        }
        return new CodePointIterator() {
            private int current = -1;
            private int offset = 0;

            public boolean hasNext() {
                return iterator.hasNext();
            }

            public boolean hasPrev() {
                return offset > 0;
            }

            private void seekToNext() {
                int b;
                while (iterator.hasNext()) {
                    b = iterator.next();
                    if ((b & 0b11_000000) != 0b10_000000) {
                        // back up one spot
                        iterator.prev();
                        return;
                    }
                }
            }

            private void seekToPrev() {
                int b;
                while (iterator.hasPrev()) {
                    b = iterator.prev();
                    if ((b & 0b11_000000) != 0b10_000000) {
                        return;
                    }
                }
            }

            public int next() {
                if (! iterator.hasNext()) throw new NoSuchElementException();
                offset++;
                // >= 1 byte
                int a = iterator.next();
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
                if (! iterator.hasNext()) {
                    // truncated
                    return current = '�';
                }
                int b = iterator.next();
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
                if (! iterator.hasNext()) {
                    // truncated
                    return current = '�';
                }
                int c = iterator.next();
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
                if (! iterator.hasNext()) {
                    // truncated
                    return current = '�';
                }
                int d = iterator.next();
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

            public int peekNext() throws NoSuchElementException {
                if (! iterator.hasNext()) throw new NoSuchElementException();
                int a = iterator.peekNext();
                if ((a & 0b1_0000000) == 0b0_0000000) {
                    // one byte
                    return a;
                }
                if ((a & 0b11_000000) == 0b10_000000) {
                    // first byte is invalid; return � instead
                    return '�';
                }
                // >= 2 bytes
                iterator.next();
                if (! iterator.hasNext()) {
                    iterator.prev();
                    // truncated
                    return '�';
                }
                int b = iterator.peekNext();
                if ((b & 0b11_000000) != 0b10_000000) {
                    // second byte is invalid; return � instead
                    iterator.prev();
                    return '�';
                }
                if ((a & 0b111_00000) == 0b110_00000) {
                    // two bytes
                    iterator.prev();
                    return a & 0b000_11111 << 6 | b & 0b00_111111;
                }
                // >= 3 bytes
                iterator.next();
                if (! iterator.hasNext()) {
                    // truncated
                    iterator.prev();
                    iterator.prev();
                    return '�';
                }
                int c = iterator.peekNext();
                if ((c & 0b11_000000) != 0b10_000000) {
                    // third byte is invalid; return � instead
                    iterator.prev();
                    iterator.prev();
                    return '�';
                }
                if ((a & 0b1111_0000) == 0b1110_0000) {
                    // three bytes
                    iterator.prev();
                    iterator.prev();
                    return a & 0b0000_1111 << 12 | b & 0b00_111111 << 6 | c & 0b00_111111;
                }
                // >= 4 bytes
                iterator.next();
                if (! iterator.hasNext()) {
                    // truncated
                    iterator.prev();
                    iterator.prev();
                    iterator.prev();
                    return '�';
                }
                int d = iterator.peekNext();
                if ((d & 0b11_000000) != 0b10_000000) {
                    // fourth byte is invalid; return � instead
                    iterator.prev();
                    iterator.prev();
                    iterator.prev();
                    return '�';
                }
                if ((a & 0b11111_000) == 0b11110_000) {
                    // four bytes
                    iterator.prev();
                    iterator.prev();
                    iterator.prev();
                    return current = a & 0b00000_111 << 18 | b & 0b00_111111 << 12 | c & 0b00_111111 << 6 | d & 0b00_111111;
                }
                // only invalid possibilities are left; return � instead
                iterator.prev();
                iterator.prev();
                iterator.prev();
                return '�';
            }

            public int prev() {
                // read backwards
                if (! iterator.hasPrev()) throw new NoSuchElementException();
                offset--;
                // >= 1 byte
                int a = iterator.prev();
                if ((a & 0b1_0000000) == 0b0_0000000) {
                    // one byte
                    return current = a;
                }
                if ((a & 0b11_000000) != 0b10_000000) {
                    // last byte is invalid; return � instead
                    seekToPrev();
                    return current = '�';
                }
                int cp = a & 0b00_111111;
                // >= 2 bytes
                a = iterator.prev();
                if ((a & 0b111_00000) == 0b110_00000) {
                    // two bytes
                    return current = a & 0b000_11111 << 6 | cp;
                }
                if ((a & 0b11_000000) != 0b10_000000) {
                    // second-to-last byte is invalid; return � instead
                    seekToPrev();
                    return current = '�';
                }
                cp |= (a & 0b00_111111) << 6;
                // >= 3 bytes
                a = iterator.prev();
                if ((a & 0b1111_0000) == 0b1110_0000) {
                    // three bytes
                    return current = a & 0b0000_1111 << 12 | cp;
                }
                if ((a & 0b11_000000) != 0b10_000000) {
                    // third-to-last byte is invalid; return � instead
                    seekToPrev();
                    return current = '�';
                }
                cp |= (a & 0b00_111111) << 12;
                // >= 4 bytes
                a = iterator.prev();
                if ((a & 0b11111_000) == 0b11110_000) {
                    // four bytes
                    return current = a & 0b00000_111 << 18 | cp;
                }
                // only invalid possibilities are left; return � instead
                seekToPrev();
                return current = '�';
            }

            public int peekPrev() throws NoSuchElementException {
                // read backwards
                if (! iterator.hasPrev()) throw new NoSuchElementException();
                // >= 1 byte
                int a = iterator.peekPrev();
                if ((a & 0b1_0000000) == 0b0_0000000) {
                    // one byte
                    return a;
                }
                if ((a & 0b11_000000) != 0b10_000000) {
                    // last byte is invalid; return � instead
                    return '�';
                }
                int cp = a & 0b00_111111;
                // >= 2 bytes
                iterator.prev();
                a = iterator.peekPrev();
                if ((a & 0b111_00000) == 0b110_00000) {
                    // two bytes
                    iterator.next();
                    return a & 0b000_11111 << 6 | cp;
                }
                if ((a & 0b11_000000) != 0b10_000000) {
                    // second-to-last byte is invalid; return � instead
                    iterator.next();
                    return '�';
                }
                cp |= (a & 0b00_111111) << 6;
                // >= 3 bytes
                iterator.prev();
                a = iterator.peekPrev();
                if ((a & 0b1111_0000) == 0b1110_0000) {
                    // three bytes
                    iterator.next();
                    iterator.next();
                    return a & 0b0000_1111 << 12 | cp;
                }
                if ((a & 0b11_000000) != 0b10_000000) {
                    // third-to-last byte is invalid; return � instead
                    iterator.next();
                    iterator.next();
                    return '�';
                }
                cp |= (a & 0b00_111111) << 12;
                // >= 4 bytes
                iterator.prev();
                a = iterator.peekPrev();
                if ((a & 0b11111_000) == 0b11110_000) {
                    // four bytes
                    iterator.next();
                    iterator.next();
                    iterator.next();
                    return a & 0b00000_111 << 18 | cp;
                }
                // only invalid possibilities are left; return � instead
                iterator.next();
                iterator.next();
                iterator.next();
                return '�';
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

            public int next() {
                if (! hasNext()) throw new NoSuchElementException();
                return current = bytes[offs + idx++];
            }

            public int peekNext() throws NoSuchElementException {
                if (! hasNext()) throw new NoSuchElementException();
                return bytes[offs + idx];
            }

            public int prev() {
                if (! hasPrev()) throw new NoSuchElementException();
                return current = bytes[offs + --idx];
            }

            public int peekPrev() throws NoSuchElementException {
                if (! hasPrev()) throw new NoSuchElementException();
                return bytes[offs + idx - 1];
            }

            public int offset() {
                return idx;
            }
        };
    }

    /**
     * Get a code point iterator for a Latin-1 encoded byte iterator.
     *
     * @param iterator the byte iterator
     * @return the code point iterator
     */
    public static CodePointIterator ofLatin1Bytes(final ByteIterator iterator) {
        if (! iterator.hasNext()) {
            return EMPTY;
        }
        final int offset = iterator.offset();
        return new CodePointIterator() {
            public boolean hasNext() {
                return iterator.hasNext();
            }

            public boolean hasPrev() {
                return offset > 0 && iterator.hasPrev();
            }

            public int next() {
                return iterator.next();
            }

            public int peekNext() throws NoSuchElementException {
                return iterator.peekNext();
            }

            public int prev() {
                if (offset == 0) throw new NoSuchElementException();
                return iterator.prev();
            }

            public int peekPrev() throws NoSuchElementException {
                return iterator.peekPrev();
            }

            public int offset() {
                return iterator.offset() - offset;
            }
        };
    }

    /**
     * The empty code point iterator.
     */
    public static final CodePointIterator EMPTY = new CodePointIterator() {
        public boolean hasNext() {
            return false;
        }

        public boolean hasPrev() {
            return false;
        }

        public int next() {
            throw new NoSuchElementException();
        }

        public int peekNext() throws NoSuchElementException {
            throw new NoSuchElementException();
        }

        public int prev() {
            throw new NoSuchElementException();
        }

        public int peekPrev() throws NoSuchElementException {
            throw new NoSuchElementException();
        }

        public int offset() {
            return 0;
        }

        public ByteIterator base64Decode(final Alphabet alphabet, final boolean requirePadding) {
            return ByteIterator.EMPTY;
        }

        public String drainToString() {
            return "";
        }
    };
}
