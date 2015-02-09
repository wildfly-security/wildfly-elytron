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
     * contents are not equal, the iterators will be positioned at the location of the first difference (i.e. the code point
     * returned by {@link #next()} will be the differing code point.  If the contents are equal, the iterators will both be
     * positioned at the end of their contents.
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
                if (peekNext() != other.peekNext()) {
                    return false;
                }
                next();
                other.next();
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
     * Get a byte iterator over the latin-1 encoding of this code point iterator.
     *
     * @return the byte iterator
     */
    public ByteIterator asLatin1() {
        return new ByteIterator() {
            public boolean hasNext() {
                return CodePointIterator.this.hasNext();
            }

            public boolean hasPrev() {
                return CodePointIterator.this.hasPrev();
            }

            public int next() throws NoSuchElementException {
                final int v = CodePointIterator.this.next();
                return v > 255 ? '?' : v;
            }

            public int peekNext() throws NoSuchElementException {
                final int v = CodePointIterator.this.peekNext();
                return v > 255 ? '?' : v;
            }

            public int prev() throws NoSuchElementException {
                final int v = CodePointIterator.this.prev();
                return v > 255 ? '?' : v;
            }

            public int peekPrev() throws NoSuchElementException {
                final int v = CodePointIterator.this.peekPrev();
                return v > 255 ? '?' : v;
            }

            public int offset() {
                return CodePointIterator.this.offset();
            }
        };
    }

    /**
     * Get a byte iterator over the UTF-8 encoding of this code point iterator.
     *
     * @return the byte iterator
     */
    public ByteIterator asUtf8() {
        return asUtf8(false);
    }

    /**
     * Get a byte iterator over the UTF-8 encoding of this code point iterator.
     *
     * @param escapeNul {@code true} to escape NUL (0) characters as two bytes, {@code false} to encode them as one byte
     * @return the byte iterator
     */
    public ByteIterator asUtf8(final boolean escapeNul) {
        return new ByteIterator() {
            // state 0 = between code points
            // state 1 = after byte 1 of 2
            // state 2 = after byte 1 of 3
            // state 3 = after byte 2 of 3
            // state 4 = after byte 1 of 4
            // state 5 = after byte 2 of 4
            // state 6 = after byte 3 of 4

            private int st;
            private int cp = -1;
            private int offset;

            public boolean hasNext() {
                return st != 0 || CodePointIterator.this.hasNext();
            }

            public boolean hasPrev() {
                return st != 0 || CodePointIterator.this.hasPrev();
            }

            public int next() throws NoSuchElementException {
                if (! hasNext()) throw new NoSuchElementException();
                offset++;
                switch (st) {
                    case 0: {
                        int cp = CodePointIterator.this.next();
                        if (cp == 0 && ! escapeNul || cp < 0x80) {
                            return cp;
                        } else if (cp < 0x800) {
                            this.cp = cp;
                            st = 1;
                            return 0b110_00000 | cp >> 6;
                        } else if (cp < 0x10000) {
                            this.cp = cp;
                            st = 2;
                            return 0b1110_0000 | cp >> 12;
                        } else if (cp < 0x110000) {
                            this.cp = cp;
                            st = 4;
                            return 0b11110_000 | cp >> 18;
                        } else {
                            this.cp = '�';
                            st = 2;
                            return 0b1110_0000 | '�' >> 12;
                        }
                    }
                    case 1:
                    case 3:
                    case 6: {
                        st = 0;
                        return 0b10_000000 | cp & 0x3f;
                    }
                    case 2: {
                        st = 3;
                        return 0b10_000000 | cp >> 6 & 0x3f;
                    }
                    case 4: {
                        st = 5;
                        return 0b10_000000 | cp >> 12 & 0x3f;
                    }
                    case 5: {
                        st = 6;
                        return 0b10_000000 | cp >> 6 & 0x3f;
                    }
                    default: {
                        throw new IllegalStateException();
                    }
                }
            }

            public int peekNext() throws NoSuchElementException {
                if (! hasNext()) throw new NoSuchElementException();
                switch (st) {
                    case 0: {
                        int cp = CodePointIterator.this.peekNext();
                        if (cp < 0x80) {
                            return cp;
                        } else if (cp < 0x800) {
                            return 0b110_00000 | cp >> 6;
                        } else if (cp < 0x10000) {
                            return 0b1110_0000 | cp >> 12;
                        } else if (cp < 0x110000) {
                            return 0b11110_000 | cp >> 18;
                        } else {
                            return 0b1110_0000 | '�' >> 12;
                        }
                    }
                    case 1:
                    case 3:
                    case 6: {
                        return 0b10_000000 | cp & 0x3f;
                    }
                    case 2:
                    case 5: {
                        return 0b10_000000 | cp >> 6 & 0x3f;
                    }
                    case 4: {
                        return 0b10_000000 | cp >> 12 & 0x3f;
                    }
                    default: {
                        throw new IllegalStateException();
                    }
                }
            }

            public int prev() throws NoSuchElementException {
                if (! hasPrev()) throw new NoSuchElementException();
                offset--;
                switch (st) {
                    case 0: {
                        int cp = CodePointIterator.this.prev();
                        if (cp == 0 && ! escapeNul || cp < 0x80) {
                            return cp;
                        } else if (cp < 0x800) {
                            this.cp = cp;
                            st = 1;
                            return 0b10_000000 | cp & 0x3f;
                        } else if (cp < 0x10000) {
                            this.cp = cp;
                            st = 3;
                            return 0b10_000000 | cp & 0x3f;
                        } else if (cp < 0x110000) {
                            this.cp = cp;
                            st = 6;
                            return 0b10_000000 | cp & 0x3f;
                        } else {
                            this.cp = '�';
                            st = 3;
                            return 0b10_000000 | '�' & 0x3f;
                        }
                    }
                    case 1: {
                        st = 0;
                        return 0b110_00000 | cp >> 6;
                    }
                    case 2: {
                        st = 0;
                        return 0b1110_0000 | cp >> 12;
                    }
                    case 3: {
                        st = 2;
                        return 0b10_000000 | cp >> 6 & 0x3f;
                    }
                    case 4: {
                        st = 0;
                        return 0b11110_000 | cp >> 18;
                    }
                    case 5: {
                        st = 4;
                        return 0b10_000000 | cp >> 12 & 0x3f;
                    }
                    case 6: {
                        st = 5;
                        return 0b10_000000 | cp >> 6 & 0x3f;
                    }
                    default: {
                        throw new IllegalStateException();
                    }
                }
            }

            public int peekPrev() throws NoSuchElementException {
                if (! hasPrev()) throw new NoSuchElementException();
                switch (st) {
                    case 0: {
                        int cp = CodePointIterator.this.peekPrev();
                        if (cp == 0 && ! escapeNul || cp < 0x80) {
                            return cp;
                        } else if (cp < 0x800) {
                            return 0b10_000000 | cp & 0x3f;
                        } else if (cp < 0x10000) {
                            return 0b10_000000 | cp & 0x3f;
                        } else if (cp < 0x110000) {
                            return 0b10_000000 | cp & 0x3f;
                        } else {
                            return 0b10_000000 | '�' & 0x3f;
                        }
                    }
                    case 1: {
                        return 0b110_00000 | cp >> 6;
                    }
                    case 2: {
                        return 0b1110_0000 | cp >> 12;
                    }
                    case 3:
                    case 6: {
                        return 0b10_000000 | cp >> 6 & 0x3f;
                    }
                    case 4: {
                        return 0b11110_000 | cp >> 18;
                    }
                    case 5: {
                        return 0b10_000000 | cp >> 12 & 0x3f;
                    }
                    default: {
                        throw new IllegalStateException();
                    }
                }
            }

            public ByteStringBuilder appendTo(final ByteStringBuilder builder) {
                if (st == 0) {
                    // this is faster
                    final int oldLen = builder.length();
                    builder.appendUtf8(CodePointIterator.this);
                    offset += builder.length() - oldLen;
                } else {
                    super.appendTo(builder);
                }
                return builder;
            }

            public int offset() {
                return offset;
            }
        };
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
                    return string.codePointAt(idx + offs);
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
                return string.codePointAt(idx + offs);
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
     * @return the code point iterator
     */
    public static CodePointIterator ofChars(final char[] chars, final int offs) {
        return ofChars(chars, offs, chars.length - offs);
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
                    return Character.codePointAt(chars, offs + idx);
                } finally {
                    idx = Character.offsetByCodePoints(chars, offs, len, offs + idx, 1) - offs;
                }
            }

            public int peekNext() throws NoSuchElementException {
                if (! hasNext()) throw new NoSuchElementException();
                return Character.codePointAt(chars, offs + idx);
            }

            public int prev() {
                if (! hasPrev()) throw new NoSuchElementException();
                idx = Character.offsetByCodePoints(chars, offs, len, offs + idx, -1) - offs;
                offset--;
                return Character.codePointAt(chars, offs + idx);
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
        return ByteIterator.ofBytes(bytes, offs, len).asUtf8String();
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
        if (len <= 0) {
            return EMPTY;
        }
        return ByteIterator.ofBytes(bytes, offs, len).asLatin1String();
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
