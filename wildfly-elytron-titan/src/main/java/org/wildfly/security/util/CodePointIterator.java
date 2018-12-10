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

import org.wildfly.common.Assert;

import java.util.NoSuchElementException;
import java.util.function.IntPredicate;

import static org.wildfly.security.util.Alphabet.Base32Alphabet;
import static org.wildfly.security.util.Alphabet.Base64Alphabet;

/**
 * A code point by code point iterator.
 *
 * @deprecated Use {@link org.wildfly.common.iteration.CodePointIterator} instead.
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
@Deprecated
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
     * Determine if the remaining contents of this iterator are identical to the given string.  If the
     * contents are not equal, the iterator will be positioned at the location of the first difference (i.e. the code point
     * returned by {@link #next()} will be the differing code point.  If the contents are equal, the iterator will be
     * positioned at the end of its contents.
     *
     * @param other the other string
     * @return {@code true} if the contents are equal, {@code false} otherwise
     */
    public boolean contentEquals(String other) {
        return contentEquals(CodePointIterator.ofString(other));
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
     * Get a sub-iterator that is delimited by the given code points.  The returned iterator offset starts at 0 and cannot
     * be backed up before that point.  The returned iterator will return {@code false} for {@code hasNext()} if the next
     * character in the encapsulated iterator is a delimiter or if the underlying iterator returns {@code false} for
     * {@code hasNext()}.
     *
     * @param delims the code point delimiters
     * @return the sub-iterator
     */
    public final CodePointIterator delimitedBy(final int... delims) {
        if ((delims == null) || (delims.length == 0) || ! hasNext()) {
            return EMPTY;
        }
        for (int delim : delims) {
            if (! Character.isValidCodePoint(delim)) {
                return EMPTY;
            }
        }
        return new CodePointIterator() {
            int offset = 0;

            public boolean hasNext() {
                return CodePointIterator.this.hasNext() && ! isDelim(CodePointIterator.this.peekNext());
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

            private boolean isDelim(int c) {
                for (int delim : delims) {
                    if (delim == c) {
                        return true;
                    }
                }
                return false;
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
     * Skip all the remaining code points in this iterator.
     * (Useful in combination with {@link #delimitedBy(int...)})
     *
     * @return the same code point iterator
     */
    public CodePointIterator skipAll() {
        while (hasNext()) next();
        return this;
    }

    /**
     * Drain all the remaining code points in this iterator to the given string builder,
     * inserting the given prefix and delimiter before and after every {@code n} code points,
     * respectively.
     *
     * @param b the string builder
     * @param prefix the prefix
     * @param delim the delimiter
     * @param n the number of code points between each prefix and delimiter
     * @return the same string builder
     */
    public StringBuilder drainTo(StringBuilder b, final String prefix, final int delim, final int n) {
        int i = 0;
        boolean insertPrefix = (prefix != null);
        boolean insertDelim = Character.isValidCodePoint(delim);
        if (hasNext()) {
            if (insertPrefix) {
                b.append(prefix);
            }
            b.appendCodePoint(next());
            i ++;
            while (hasNext()) {
                if (i == n) {
                    if (insertDelim) {
                        b.appendCodePoint(delim);
                    }
                    if (insertPrefix) {
                        b.append(prefix);
                    }
                    b.appendCodePoint(next());
                    i = 1;
                } else {
                    b.appendCodePoint(next());
                    i ++;
                }
            }
        }
        return b;
    }

    /**
     * Drain all the remaining code points in this iterator to the given string builder,
     * inserting the given delimiter after every {@code n} code points.
     *
     * @param b the string builder
     * @param delim the delimiter
     * @param n the number of code points between each delimiter
     * @return the same string builder
     */
    public StringBuilder drainTo(StringBuilder b, final int delim, final int n) {
        return drainTo(b, null, delim, n);
    }

    /**
     * Drain all the remaining code points in this iterator to the given string builder,
     * inserting the given prefix before every {@code n} code points.
     *
     * @param b the string builder
     * @param prefix the prefix
     * @param n the number of code points between each prefix
     * @return the same string builder
     */
    public StringBuilder drainTo(StringBuilder b, final String prefix, final int n) {
        return drainTo(b, prefix, -1, n);
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
     * Drain all the remaining code points in this iterator to a new string,
     * inserting the given prefix and delimiter before and after every {@code n}
     * code points, respectively.
     *
     * @param prefix the prefix
     * @param delim the delimiter
     * @param n the number of code points between each prefix and delimiter
     * @return the string
     */
    public String drainToString(final String prefix, final int delim, final int n) {
        return hasNext() ? drainTo(new StringBuilder(), prefix, delim, n).toString() : "";
    }

    /**
     * Drain all the remaining code points in this iterator to a new string,
     * inserting the given delimiter after every {@code n} code points.
     *
     * @param delim the delimiter
     * @param n the number of code points between each delimiter
     * @return the string
     */
    public String drainToString(final int delim, final int n) {
        return hasNext() ? drainTo(new StringBuilder(), null, delim, n).toString() : "";
    }

    /**
     * Drain all the remaining code points in this iterator to a new string,
     * inserting the given prefix before every {@code n} code points.
     *
     * @param prefix the prefix
     * @param n the number of code points between each prefix
     * @return the string
     */
    public String drainToString(final String prefix, final int n) {
        return hasNext() ? drainTo(new StringBuilder(), prefix, -1, n).toString() : "";
    }

    /**
     * Base64-decode the current stream.
     *
     * @param alphabet the alphabet to use
     * @param requirePadding {@code true} to require padding, {@code false} if padding is optional
     * @return an iterator over the decoded bytes
     */
    public ByteIterator base64Decode(final Base64Alphabet alphabet, boolean requirePadding) {
        return super.base64Decode(alphabet, requirePadding);
    }

    /**
     * Base64-decode the current stream.
     *
     * @param alphabet the alphabet to use
     * @return an iterator over the decoded bytes
     */
    public ByteIterator base64Decode(final Base64Alphabet alphabet) {
        return super.base64Decode(alphabet, true);
    }

    /**
     * Base64-decode the current stream.
     *
     * @return an iterator over the decoded bytes
     */
    public ByteIterator base64Decode() {
        return super.base64Decode(Base64Alphabet.STANDARD, true);
    }

    /**
     * Base32-decode the current stream.
     *
     * @param alphabet the alphabet to use
     * @param requirePadding {@code true} to require padding, {@code false} if padding is optional
     * @return an iterator over the decoded bytes
     */
    public ByteIterator base32Decode(final Base32Alphabet alphabet, boolean requirePadding) {
        return super.base32Decode(alphabet, requirePadding);
    }

    /**
     * Base32-decode the current stream.
     *
     * @param alphabet the alphabet to use
     * @return an iterator over the decoded bytes
     */
    public ByteIterator base32Decode(final Base32Alphabet alphabet) {
        return super.base32Decode(alphabet, true);
    }

    /**
     * Base32-decode the current stream.
     *
     * @return an iterator over the decoded bytes
     */
    public ByteIterator base32Decode() {
        return super.base32Decode(Base32Alphabet.STANDARD, true);
    }

    /**
     * Hex-decode the current stream.
     *
     * @return an iterator over the decoded bytes
     */
    public ByteIterator hexDecode() {
        return super.hexDecode();
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
                        throw Assert.impossibleSwitchCase(st);
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
                        throw Assert.impossibleSwitchCase(st);
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
                        throw Assert.impossibleSwitchCase(st);
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
                        throw Assert.impossibleSwitchCase(st);
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
     * Get a sub-iterator that removes the following code points: <code>10</code>(\n) and <code>13</code>(\r).
     *
     * @return the code point iterator
     */
    public CodePointIterator skipCrLf() {
        return skip(value -> value == '\n' || value == '\r');
    }

    /**
     * Get a sub-iterator that removes code points based on a <code>predicate</code>.
     *
     * @param predicate a {@link IntPredicate} that evaluates the code points that should be skipper. Returning true from the predicate
     * indicates that the code point must be skipped.
     * @return the code point iterator
     */
    public CodePointIterator skip(IntPredicate predicate) {
        if (!hasNext()) {
            return EMPTY;
        }

        return new CodePointIterator() {
            public boolean hasNext() {
                return CodePointIterator.this.hasNext() && !skip(peekNext());
            }

            public boolean hasPrev() {
                return CodePointIterator.this.hasPrev() && !skip(peekPrev());
            }

            public int next() {
                if (!hasNext()) {
                    throw new NoSuchElementException();
                }

                return CodePointIterator.this.next();
            }

            public int peekNext() throws NoSuchElementException {
                if (!CodePointIterator.this.hasNext()) {
                    throw new NoSuchElementException();
                }

                int next = seekNext(CodePointIterator.this.peekNext());

                if (!skip(next)) {
                    return next;
                }

                return next;
            }

            private int seekNext(int next) throws NoSuchElementException {
                if (!CodePointIterator.this.hasNext()) {
                    return next;
                }

                next = CodePointIterator.this.next();

                if (skip(next)) {
                    return seekNext(next);
                }

                CodePointIterator.this.prev();

                return next;
            }

            public int prev() {
                if (!hasPrev()) {
                    throw new NoSuchElementException();
                }

                return CodePointIterator.this.prev();
            }

            public int peekPrev() throws NoSuchElementException {
                if (!CodePointIterator.this.hasPrev()) {
                    throw new NoSuchElementException();
                }

                int prev = seekPrev(CodePointIterator.this.peekPrev());

                if (!skip(prev)) {
                    return prev;
                }

                return prev;
            }

            private int seekPrev(int prev) throws NoSuchElementException {
                if (!CodePointIterator.this.hasPrev()) {
                    return prev;
                }

                prev = CodePointIterator.this.prev();

                if (skip(prev)) {
                    return seekPrev(prev);
                }

                CodePointIterator.this.next();

                return prev;
            }

            public int offset() {
                return CodePointIterator.this.offset();
            }

            private boolean skip(int c) {
                return predicate.test(c);
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

        public ByteIterator base64Decode(final Base64Alphabet alphabet, final boolean requirePadding) {
            return ByteIterator.EMPTY;
        }

        public String drainToString() {
            return "";
        }
    };
}
