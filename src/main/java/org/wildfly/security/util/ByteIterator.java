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

import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Arrays;
import java.util.NoSuchElementException;

import javax.crypto.Mac;

/**
 * A byte iterator.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public abstract class ByteIterator extends NumericIterator {

    private static final int OP_BUFFER_SIZE = 8192;

    private static final ThreadLocal<byte[]> OP_BUFFER = new ThreadLocal<byte[]>() {
        protected byte[] initialValue() {
            return new byte[OP_BUFFER_SIZE];
        }
    };

    /**
     * Determine if there are more bytes after the current byte.
     *
     * @return {@code true} if there are more bytes, {@code false} otherwise
     */
    public abstract boolean hasNext();

    /**
     * Determine if there are more bytes before the current byte.
     *
     * @return {@code true} if there are more bytes, {@code false} otherwise
     */
    public abstract boolean hasPrev();

    /**
     * Get the next byte.
     *
     * @return the next byte
     * @throws NoSuchElementException if {@link #hasNext()} returns {@code false}
     */
    public abstract int next() throws NoSuchElementException;

    /**
     * Peek at the next byte without advancing.
     *
     * @return the next byte
     * @throws NoSuchElementException if {@link #hasNext()} returns {@code false}
     */
    public abstract int peekNext() throws NoSuchElementException;

    /**
     * Get the previous byte.
     *
     * @return the previous byte
     * @throws NoSuchElementException if {@link #hasPrev()} returns {@code false}
     */
    public abstract int prev() throws NoSuchElementException;

    /**
     * Peek at the previous byte without moving backwards.
     *
     * @return the previous byte
     * @throws NoSuchElementException if {@link #hasPrev()} returns {@code false}
     */
    public abstract int peekPrev() throws NoSuchElementException;

    /**
     * Get the current offset, in bytes.
     *
     * @return the byte offset
     */
    public abstract int offset();

    public ByteStringBuilder appendTo(final ByteStringBuilder builder) {
        final byte[] buffer = OP_BUFFER.get();
        int cnt = drain(buffer);
        while (cnt > 0) {
            builder.append(buffer, 0, cnt);
            cnt = drain(buffer);
        }
        return builder;
    }

    public void update(MessageDigest digest) throws IllegalStateException {
        final byte[] buffer = OP_BUFFER.get();
        int cnt = drain(buffer);
        while (cnt > 0) {
            digest.update(buffer, 0, cnt);
            cnt = drain(buffer);
        }
    }

    public ByteIterator doFinal(MessageDigest digest) throws IllegalStateException {
        update(digest);
        return ByteIterator.ofBytes(digest.digest());
    }

    public void update(Mac mac) throws IllegalStateException {
        final byte[] buffer = OP_BUFFER.get();
        int cnt = drain(buffer);
        while (cnt > 0) {
            mac.update(buffer, 0, cnt);
            cnt = drain(buffer);
        }
    }

    public ByteIterator doFinal(Mac mac) throws IllegalStateException {
        return ByteIterator.ofBytes(mac.doFinal(drain()));
    }

    public void update(Signature signature) throws IllegalStateException {
        final byte[] buffer = OP_BUFFER.get();
        try {
            int cnt = drain(buffer);
            while (cnt > 0) {
                signature.update(buffer, 0, cnt);
                cnt = drain(buffer);
            }
            signature.update(drain());
        } catch (SignatureException e) {
            throw new IllegalStateException(e);
        }
    }

    public ByteIterator sign(Signature signature) throws IllegalStateException {
        update(signature);
        try {
            return ByteIterator.ofBytes(signature.sign());
        } catch (SignatureException e) {
            throw new IllegalStateException(e);
        }
    }

    public boolean verify(Signature signature) throws IllegalStateException {
        final byte[] buffer = OP_BUFFER.get();
        try {
            int cnt = drain(buffer);
            while (cnt > 0) {
                signature.update(buffer, 0, cnt);
                cnt = drain(buffer);
            }
            return signature.verify(NO_BYTES);
        } catch (SignatureException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * Base64-decode the current stream, assuming that the byte data is encoded in an ASCII-derived encoding.
     *
     * @param alphabet the alphabet to use
     * @param requirePadding {@code true} to require padding, {@code false} if padding is optional
     * @return an iterator over the decoded bytes
     */
    public ByteIterator base64Decode(final Alphabet alphabet, boolean requirePadding) {
        return super.base64Decode(alphabet, requirePadding);
    }

    /**
     * Base64-decode the current stream, assuming that the byte data is encoded in an ASCII-derived encoding.
     *
     * @param alphabet the alphabet to use
     * @return an iterator over the decoded bytes
     */
    public ByteIterator base64Decode(final Alphabet alphabet) {
        return super.base64Decode(alphabet, true);
    }

    /**
     * Base64-decode the current stream, assuming that the byte data is encoded in an ASCII-derived encoding.
     *
     * @return an iterator over the decoded bytes
     */
    public ByteIterator base64Decode() {
        return super.base64Decode(Alphabet.STANDARD, true);
    }

    /**
     * Base64-encode the current stream.
     *
     * @param alphabet the alphabet to use
     * @param addPadding {@code true} to add trailing padding, {@code false} to leave it off
     * @return an iterator over the encoded characters
     */
    public CodePointIterator base64Encode(final Alphabet alphabet, final boolean addPadding) {
        if (alphabet.littleEndian) {
            return new Base64EncodingCodePointIterator(addPadding) {
                int calc0(final int b0) {
                    // d0 = r0[5..0]
                    return alphabet.encode(b0 & 0x3f);
                }

                int calc1(final int b0, final int b1) {
                    // d1 = r1[3..0] + r0[7..6]
                    return alphabet.encode((b1 << 2 | b0 >> 6) & 0x3f);
                }

                int calc2(final int b1, final int b2) {
                    // d2 = r2[1..0] + r1[7..4]
                    return alphabet.encode((b2 << 4 | b1 >> 4) & 0x3f);
                }

                int calc3(final int b2) {
                    // d3 = r2[7..2]
                    return alphabet.encode((b2 >> 2) & 0x3f);
                }
            };
        } else {
            return new Base64EncodingCodePointIterator(addPadding) {
                int calc0(final int b0) {
                    // d0 = r0[7..2]
                    return alphabet.encode((b0 >> 2) & 0x3f);
                }

                int calc1(final int b0, final int b1) {
                    // d1 = r0[1..0] + r1[7..4]
                    return alphabet.encode((b0 << 4 | b1 >> 4) & 0x3f);
                }

                int calc2(final int b1, final int b2) {
                    // d2 = r1[3..0] + r2[7..6]
                    return alphabet.encode((b1 << 2 | b2 >> 6) & 0x3f);
                }

                int calc3(final int b2) {
                    // d3 = r2[5..0]
                    return alphabet.encode(b2 & 0x3f);
                }
            };
        }
    }

    /**
     * Base64-encode the current stream.
     *
     * @param alphabet the alphabet to use
     * @return an iterator over the encoded characters
     */
    public CodePointIterator base64Encode(final Alphabet alphabet) {
        return base64Encode(alphabet, true);
    }

    /**
     * Base64-encode the current stream.
     *
     * @return an iterator over the encoded characters
     */
    public CodePointIterator base64Encode() {
        return base64Encode(Alphabet.STANDARD, true);
    }

    /**
     * Hex-encode the current stream.
     *
     * @return an iterator over the encoded characters
     */
    public CodePointIterator hexEncode() {
        return new CodePointIterator() {
            int b;
            boolean lo;

            public boolean hasNext() {
                return lo || ByteIterator.this.hasNext();
            }

            public boolean hasPrev() {
                return lo || ByteIterator.this.hasPrev();
            }

            private int hex(final int i) {
                return i < 10 ? '0' + i : 'a' + i - 10;
            }

            public int next() throws NoSuchElementException {
                if (! hasNext()) throw new NoSuchElementException();
                if (lo) {
                    lo = false;
                    return hex(b & 0xf);
                } else {
                    b = ByteIterator.this.next();
                    lo = true;
                    return hex(b >> 4);
                }
            }

            public int peekNext() throws NoSuchElementException {
                if (! hasNext()) throw new NoSuchElementException();
                if (lo) {
                    return hex(b & 0xf);
                } else {
                    return hex(ByteIterator.this.peekNext() >> 4);
                }
            }

            public int prev() throws NoSuchElementException {
                if (! hasPrev()) throw new NoSuchElementException();
                if (lo) {
                    lo = false;
                    ByteIterator.this.prev();
                    return hex(b >> 4);
                } else {
                    b = ByteIterator.this.peekPrev();
                    lo = true;
                    return hex(b & 0xf);
                }
            }

            public int peekPrev() throws NoSuchElementException {
                if (! hasPrev()) throw new NoSuchElementException();
                if (lo) {
                    return hex(b >> 4);
                } else {
                    return hex(ByteIterator.this.peekPrev() & 0xf);
                }
            }

            public int offset() {
                return ByteIterator.this.offset() * 2 + (lo ? 1 : 0);
            }
        };
    }

    /**
     * Get this byte iterator as a UTF-8 string.
     *
     * @return the code point iterator
     */
    public CodePointIterator asUtf8String() {
        if (! hasNext()) {
            return CodePointIterator.EMPTY;
        }
        return new CodePointIterator() {
            private int offset = 0;

            public boolean hasNext() {
                return ByteIterator.this.hasNext();
            }

            public boolean hasPrev() {
                return offset > 0;
            }

            private void seekToNext() {
                int b;
                while (ByteIterator.this.hasNext()) {
                    b = ByteIterator.this.next();
                    if ((b & 0b11_000000) != 0b10_000000) {
                        // back up one spot
                        ByteIterator.this.prev();
                        return;
                    }
                }
            }

            private void seekToPrev() {
                int b;
                while (ByteIterator.this.hasPrev()) {
                    b = ByteIterator.this.prev();
                    if ((b & 0b11_000000) != 0b10_000000) {
                        return;
                    }
                }
            }

            public int next() {
                if (! ByteIterator.this.hasNext()) throw new NoSuchElementException();
                offset++;
                // >= 1 byte
                int a = ByteIterator.this.next();
                if ((a & 0b1_0000000) == 0b0_0000000) {
                    // one byte
                    return a;
                }
                if ((a & 0b11_000000) == 0b10_000000) {
                    // first byte is invalid; return � instead
                    seekToNext();
                    return '�';
                }
                // >= 2 bytes
                if (! ByteIterator.this.hasNext()) {
                    // truncated
                    return '�';
                }
                int b = ByteIterator.this.next();
                if ((b & 0b11_000000) != 0b10_000000) {
                    // second byte is invalid; return � instead
                    seekToNext();
                    return '�';
                }
                if ((a & 0b111_00000) == 0b110_00000) {
                    // two bytes
                    return (a & 0b000_11111) << 6 | b & 0b00_111111;
                }
                // >= 3 bytes
                if (! ByteIterator.this.hasNext()) {
                    // truncated
                    return '�';
                }
                int c = ByteIterator.this.next();
                if ((c & 0b11_000000) != 0b10_000000) {
                    // third byte is invalid; return � instead
                    seekToNext();
                    return '�';
                }
                if ((a & 0b1111_0000) == 0b1110_0000) {
                    // three bytes
                    return (a & 0b0000_1111) << 12 | (b & 0b00_111111) << 6 | c & 0b00_111111;
                }
                // >= 4 bytes
                if (! ByteIterator.this.hasNext()) {
                    // truncated
                    return '�';
                }
                int d = ByteIterator.this.next();
                if ((d & 0b11_000000) != 0b10_000000) {
                    // fourth byte is invalid; return � instead
                    seekToNext();
                    return '�';
                }
                if ((a & 0b11111_000) == 0b11110_000) {
                    // four bytes
                    return (a & 0b00000_111) << 18 | (b & 0b00_111111) << 12 | (c & 0b00_111111) << 6 | d & 0b00_111111;
                }
                // only invalid possibilities are left; return � instead
                seekToNext();
                return '�';
            }

            public int peekNext() throws NoSuchElementException {
                if (! ByteIterator.this.hasNext()) throw new NoSuchElementException();
                int a = ByteIterator.this.peekNext();
                if ((a & 0b1_0000000) == 0b0_0000000) {
                    // one byte
                    return a;
                }
                if ((a & 0b11_000000) == 0b10_000000) {
                    // first byte is invalid; return � instead
                    return '�';
                }
                // >= 2 bytes
                ByteIterator.this.next();
                if (! ByteIterator.this.hasNext()) {
                    ByteIterator.this.prev();
                    // truncated
                    return '�';
                }
                int b = ByteIterator.this.peekNext();
                if ((b & 0b11_000000) != 0b10_000000) {
                    // second byte is invalid; return � instead
                    ByteIterator.this.prev();
                    return '�';
                }
                if ((a & 0b111_00000) == 0b110_00000) {
                    // two bytes
                    ByteIterator.this.prev();
                    return (a & 0b000_11111) << 6 | b & 0b00_111111;
                }
                // >= 3 bytes
                ByteIterator.this.next();
                if (! ByteIterator.this.hasNext()) {
                    // truncated
                    ByteIterator.this.prev();
                    ByteIterator.this.prev();
                    return '�';
                }
                int c = ByteIterator.this.peekNext();
                if ((c & 0b11_000000) != 0b10_000000) {
                    // third byte is invalid; return � instead
                    ByteIterator.this.prev();
                    ByteIterator.this.prev();
                    return '�';
                }
                if ((a & 0b1111_0000) == 0b1110_0000) {
                    // three bytes
                    ByteIterator.this.prev();
                    ByteIterator.this.prev();
                    return (a & 0b0000_1111) << 12 | (b & 0b00_111111) << 6 | c & 0b00_111111;
                }
                // >= 4 bytes
                ByteIterator.this.next();
                if (! ByteIterator.this.hasNext()) {
                    // truncated
                    ByteIterator.this.prev();
                    ByteIterator.this.prev();
                    ByteIterator.this.prev();
                    return '�';
                }
                int d = ByteIterator.this.peekNext();
                if ((d & 0b11_000000) != 0b10_000000) {
                    // fourth byte is invalid; return � instead
                    ByteIterator.this.prev();
                    ByteIterator.this.prev();
                    ByteIterator.this.prev();
                    return '�';
                }
                if ((a & 0b11111_000) == 0b11110_000) {
                    // four bytes
                    ByteIterator.this.prev();
                    ByteIterator.this.prev();
                    ByteIterator.this.prev();
                    return (a & 0b00000_111) << 18 | (b & 0b00_111111) << 12 | (c & 0b00_111111) << 6 | d & 0b00_111111;
                }
                // only invalid possibilities are left; return � instead
                ByteIterator.this.prev();
                ByteIterator.this.prev();
                ByteIterator.this.prev();
                return '�';
            }

            public int prev() {
                // read backwards
                if (! ByteIterator.this.hasPrev()) throw new NoSuchElementException();
                offset--;
                // >= 1 byte
                int a = ByteIterator.this.prev();
                if ((a & 0b1_0000000) == 0b0_0000000) {
                    // one byte
                    return a;
                }
                if ((a & 0b11_000000) != 0b10_000000) {
                    // last byte is invalid; return � instead
                    seekToPrev();
                    return '�';
                }
                int cp = a & 0b00_111111;
                // >= 2 bytes
                a = ByteIterator.this.prev();
                if ((a & 0b111_00000) == 0b110_00000) {
                    // two bytes
                    return (a & 0b000_11111) << 6 | cp;
                }
                if ((a & 0b11_000000) != 0b10_000000) {
                    // second-to-last byte is invalid; return � instead
                    seekToPrev();
                    return '�';
                }
                cp |= (a & 0b00_111111) << 6;
                // >= 3 bytes
                a = ByteIterator.this.prev();
                if ((a & 0b1111_0000) == 0b1110_0000) {
                    // three bytes
                    return (a & 0b0000_1111) << 12 | cp;
                }
                if ((a & 0b11_000000) != 0b10_000000) {
                    // third-to-last byte is invalid; return � instead
                    seekToPrev();
                    return '�';
                }
                cp |= (a & 0b00_111111) << 12;
                // >= 4 bytes
                a = ByteIterator.this.prev();
                if ((a & 0b11111_000) == 0b11110_000) {
                    // four bytes
                    return (a & 0b00000_111) << 18 | cp;
                }
                // only invalid possibilities are left; return � instead
                seekToPrev();
                return '�';
            }

            public int peekPrev() throws NoSuchElementException {
                // read backwards
                if (! ByteIterator.this.hasPrev()) throw new NoSuchElementException();
                // >= 1 byte
                int a = ByteIterator.this.peekPrev();
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
                ByteIterator.this.prev();
                a = ByteIterator.this.peekPrev();
                if ((a & 0b111_00000) == 0b110_00000) {
                    // two bytes
                    ByteIterator.this.next();
                    return (a & 0b000_11111) << 6 | cp;
                }
                if ((a & 0b11_000000) != 0b10_000000) {
                    // second-to-last byte is invalid; return � instead
                    ByteIterator.this.next();
                    return '�';
                }
                cp |= (a & 0b00_111111) << 6;
                // >= 3 bytes
                ByteIterator.this.prev();
                a = ByteIterator.this.peekPrev();
                if ((a & 0b1111_0000) == 0b1110_0000) {
                    // three bytes
                    ByteIterator.this.next();
                    ByteIterator.this.next();
                    return (a & 0b0000_1111) << 12 | cp;
                }
                if ((a & 0b11_000000) != 0b10_000000) {
                    // third-to-last byte is invalid; return � instead
                    ByteIterator.this.next();
                    ByteIterator.this.next();
                    return '�';
                }
                cp |= (a & 0b00_111111) << 12;
                // >= 4 bytes
                ByteIterator.this.prev();
                a = ByteIterator.this.peekPrev();
                if ((a & 0b11111_000) == 0b11110_000) {
                    // four bytes
                    ByteIterator.this.next();
                    ByteIterator.this.next();
                    ByteIterator.this.next();
                    return (a & 0b00000_111) << 18 | cp;
                }
                // only invalid possibilities are left; return � instead
                ByteIterator.this.next();
                ByteIterator.this.next();
                ByteIterator.this.next();
                return '�';
            }

            public int offset() {
                return offset;
            }
        };
    }

    /**
     * Get this byte iterator as a Latin-1 string.
     *
     * @return the code point iterator
     */
    public CodePointIterator asLatin1String() {
        if (! hasNext()) {
            return CodePointIterator.EMPTY;
        }
        final int offset = offset();
        return new CodePointIterator() {
            public boolean hasNext() {
                return ByteIterator.this.hasNext();
            }

            public boolean hasPrev() {
                return offset > 0 && ByteIterator.this.hasPrev();
            }

            public int next() {
                return ByteIterator.this.next();
            }

            public int peekNext() throws NoSuchElementException {
                return ByteIterator.this.peekNext();
            }

            public int prev() {
                if (offset == 0) throw new NoSuchElementException();
                return ByteIterator.this.prev();
            }

            public int peekPrev() throws NoSuchElementException {
                return ByteIterator.this.peekPrev();
            }

            public int offset() {
                return ByteIterator.this.offset() - offset;
            }
        };
    }

    /**
     * Determine if the remaining contents of this iterator are identical to the remaining contents of the other iterator.  If the
     * contents are not equal, the iterators will be positioned at the location of the first difference.  If the contents
     * are equal, the iterators will both be positioned at the end of their contents.
     *
     * @param other the other byte iterator
     * @return {@code true} if the contents are equal, {@code false} otherwise
     */
    public final boolean contentEquals(ByteIterator other) {
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
     * Return a copy of this iterator which is limited to the given number of bytes after the current one.  Advancing
     * the returned iterator will also advance this one.
     *
     * @param size the number of bytes
     * @return the limited byte iterator
     */
    public final ByteIterator limitedTo(final int size) {
        if (size <= 0 || ! hasNext()) {
            return EMPTY;
        }
        return new ByteIterator() {
            int offset = 0;

            public boolean hasNext() {
                return offset < size && ByteIterator.this.hasNext();
            }

            public boolean hasPrev() {
                return offset > 0;
            }

            public int next() {
                if (offset == size) {
                    throw new NoSuchElementException();
                }
                offset ++;
                return ByteIterator.this.next();
            }

            public int peekNext() throws NoSuchElementException {
                if (offset == size) {
                    throw new NoSuchElementException();
                }
                return ByteIterator.this.peekNext();
            }

            public int prev() {
                if (offset == 0) {
                    throw new NoSuchElementException();
                }
                offset --;
                return ByteIterator.this.prev();
            }

            public int peekPrev() throws NoSuchElementException {
                if (offset == 0) {
                    throw new NoSuchElementException();
                }
                return ByteIterator.this.peekPrev();
            }

            public int drain(final byte[] dst, final int offs, final int len) {
                return super.drain(dst, offs, Math.min(len, size - offset));
            }

            public int offset() {
                return offset;
            }
        };
    }

    /**
     * Get a sub-iterator that is delimited by the given byte.  The returned iterator offset starts at 0 and cannot
     * be backed up before that point.  The returned iterator will return {@code false} for {@code hasNext()} if the next
     * character in the encapsulated iterator is a delimiter or if the underlying iterator returns {@code false} for
     * {@code hasNext()}.
     *
     * @param delim the byte delimiter
     * @return the sub-iterator
     */
    public final ByteIterator delimitedBy(final int delim) {
        if (delim < 0 || delim > 0xff || ! hasNext()) {
            return EMPTY;
        }
        return new ByteIterator() {
            int offset = 0;
            int current = -1;

            public boolean hasNext() {
                return ByteIterator.this.hasNext() && delim != ByteIterator.this.peekNext();
            }

            public boolean hasPrev() {
                return offset > 0;
            }

            public int next() {
                int n = ByteIterator.this.peekNext();
                if (n == delim) {
                    current = -1;
                    throw new NoSuchElementException();
                }
                offset ++;
                return current = ByteIterator.this.next();
            }

            public int peekNext() throws NoSuchElementException {
                int n = ByteIterator.this.peekNext();
                if (n == delim) {
                    throw new NoSuchElementException();
                }
                return n;
            }

            public int prev() {
                if (offset == 0) {
                    current = -1;
                    throw new NoSuchElementException();
                }
                offset --;
                return current = ByteIterator.this.prev();
            }

            public int peekPrev() throws NoSuchElementException {
                if (offset == 0) {
                    throw new NoSuchElementException();
                }
                return ByteIterator.this.peekPrev();
            }

            public int offset() {
                return offset;
            }
        };
    }

    /**
     * Get a byte iterator which translates this byte iterator through an interleaving table.  The table should be
     * 256 entries in size or exceptions may result.
     *
     * @param table the interleaving table
     * @return the interleaving byte iterator
     */
    public ByteIterator interleavedWith(final byte[] table) {
        return new ByteIterator() {
            public boolean hasNext() {
                return ByteIterator.this.hasNext();
            }

            public boolean hasPrev() {
                return ByteIterator.this.hasPrev();
            }

            public int next() throws NoSuchElementException {
                return table[ByteIterator.this.next()] & 0xff;
            }

            public int peekNext() throws NoSuchElementException {
                return table[ByteIterator.this.peekNext()] & 0xff;
            }

            public int prev() throws NoSuchElementException {
                return table[ByteIterator.this.prev()] & 0xff;
            }

            public int peekPrev() throws NoSuchElementException {
                return table[ByteIterator.this.peekPrev()] & 0xff;
            }

            public int offset() {
                return ByteIterator.this.offset();
            }
        };
    }

    /**
     * Get a byte iterator which translates this byte iterator through an interleaving table.  The table should be
     * 256 entries in size or exceptions may result.
     *
     * @param table the interleaving table
     * @return the interleaving byte iterator
     */
    public ByteIterator interleavedWith(final int[] table) {
        return new ByteIterator() {
            public boolean hasNext() {
                return ByteIterator.this.hasNext();
            }

            public boolean hasPrev() {
                return ByteIterator.this.hasPrev();
            }

            public int next() throws NoSuchElementException {
                return table[ByteIterator.this.next()] & 0xff;
            }

            public int peekNext() throws NoSuchElementException {
                return table[ByteIterator.this.peekNext()] & 0xff;
            }

            public int prev() throws NoSuchElementException {
                return table[ByteIterator.this.prev()] & 0xff;
            }

            public int peekPrev() throws NoSuchElementException {
                return table[ByteIterator.this.peekPrev()] & 0xff;
            }

            public int offset() {
                return ByteIterator.this.offset();
            }
        };
    }

    /**
     * Drain all the remaining bytes in this iterator to the given stream.
     *
     * @param stream the stream
     * @return the same stream
     */
    public ByteArrayOutputStream drainTo(ByteArrayOutputStream stream) {
        while (hasNext()) {
            stream.write(next());
        }
        return stream;
    }

    /**
     * Drain all the remaining bytes in this iterator.
     *
     * @return the remaining bytes as a single array
     */
    public byte[] drain() {
        return drainTo(new ByteArrayOutputStream()).toByteArray();
    }

    public int drain(byte[] dst) {
        return drain(dst, 0, dst.length);
    }

    public int drain(byte[] dst, int offs, int len) {
        for (int i = 0; i < len; i ++) {
            if (! hasNext()) return i;
            dst[offs + i] = (byte) next();
        }
        return len;
    }

    /**
     * Get a byte iterator for a byte array.
     *
     * @param bytes the array
     * @return the byte iterator
     */
    public static ByteIterator ofBytes(final byte... bytes) {
        return ofBytes(bytes, 0, bytes.length);
    }

    /**
     * Get a byte iterator for a byte array.
     *
     * @param bytes the array
     * @param offs the array offset
     * @param len the number of bytes to include
     * @return the byte iterator
     */
    public static ByteIterator ofBytes(final byte[] bytes, final int offs, final int len) {
        if (len <= 0) {
            return EMPTY;
        }
        return new ByteIterator() {
            private int idx = 0;

            public boolean hasNext() {
                return idx < len;
            }

            public boolean hasPrev() {
                return idx > 0;
            }

            public int next() {
                if (! hasNext()) throw new NoSuchElementException();
                return bytes[offs + idx++] & 0xff;
            }

            public int prev() {
                if (! hasPrev()) throw new NoSuchElementException();
                return bytes[offs + --idx] & 0xff;
            }

            public int peekNext() throws NoSuchElementException {
                if (! hasNext()) throw new NoSuchElementException();
                return bytes[offs + idx] & 0xff;
            }

            public int peekPrev() throws NoSuchElementException {
                if (! hasPrev()) throw new NoSuchElementException();
                return bytes[offs + idx - 1] & 0xff;
            }

            public int offset() {
                return idx;
            }

            public void update(final MessageDigest digest) throws IllegalStateException {
                digest.update(bytes, offs + idx, len - idx);
                idx = len;
            }

            public ByteIterator doFinal(final MessageDigest digest) throws IllegalStateException {
                update(digest);
                return ByteIterator.ofBytes(digest.digest());
            }

            public void update(final Mac mac) throws IllegalStateException {
                mac.update(bytes, offs + idx, len - idx);
                idx = len;
            }

            public ByteIterator doFinal(final Mac mac) throws IllegalStateException {
                update(mac);
                return ByteIterator.ofBytes(mac.doFinal());
            }

            public void update(final Signature signature) throws IllegalStateException {
                try {
                    signature.update(bytes, offs + idx, len - idx);
                    idx = len;
                } catch (SignatureException e) {
                    throw new IllegalStateException(e);
                }
            }

            public boolean verify(final Signature signature) throws IllegalStateException {
                try {
                    return signature.verify(bytes, offs + idx, len - idx);
                } catch (SignatureException e) {
                    throw new IllegalStateException(e);
                } finally {
                    idx = len;
                }
            }

            public ByteArrayOutputStream drainTo(final ByteArrayOutputStream stream) {
                stream.write(bytes, offs + idx, len - idx);
                idx = len;
                return stream;
            }

            public byte[] drain() {
                try {
                    return Arrays.copyOfRange(bytes, offs + idx, offs + len);
                } finally {
                    idx = len;
                }
            }

            public int drain(final byte[] dst, final int offs, final int dlen) {
                int cnt = Math.min(len - idx, dlen);
                System.arraycopy(bytes, offs + idx, dst, offs, cnt);
                idx += cnt;
                return cnt;
            }

            public ByteStringBuilder appendTo(final ByteStringBuilder builder) {
                builder.append(bytes, offs + idx, len - idx);
                idx = len;
                return builder;
            }
        };
    }

    /**
     * Get a byte iterator for a byte array with interleave.
     *
     * @param bytes the array
     * @param offs the array offset
     * @param len the number of bytes to include
     * @param interleave the interleave table to use
     * @return the byte iterator
     */
    public static ByteIterator ofBytes(final byte[] bytes, final int offs, final int len, final int[] interleave) {
        if (len <= 0) {
            return EMPTY;
        }
        return new ByteIterator() {
            private int idx = 0;

            public boolean hasNext() {
                return idx < len;
            }

            public boolean hasPrev() {
                return idx > 0;
            }

            public int next() {
                if (!hasNext()) throw new NoSuchElementException();
                return bytes[offs + interleave[idx++]] & 0xff;
            }

            public int prev() {
                if (!hasPrev()) throw new NoSuchElementException();
                return bytes[offs + interleave[--idx]] & 0xff;
            }

            public int peekNext() throws NoSuchElementException {
                if (!hasNext()) throw new NoSuchElementException();
                return bytes[offs + interleave[idx]] & 0xff;
            }

            public int peekPrev() throws NoSuchElementException {
                if (!hasPrev()) throw new NoSuchElementException();
                return bytes[offs + interleave[idx - 1]] & 0xff;
            }

            public int offset() {
                return idx;
            }
        };
    }

    /**
     * Get a byte iterator for a byte array with interleave.
     *
     * @param bytes the array
     * @param interleave the interleave table to use
     * @return the byte iterator
     */
    public static ByteIterator ofBytes(final byte[] bytes, final int[] interleave) {
        return ofBytes(bytes, 0, bytes.length, interleave);
    }

    private static final byte[] NO_BYTES = new byte[0];

    /**
     * The empty byte iterator.
     */
    public static final ByteIterator EMPTY = new ByteIterator() {
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

        public byte[] drain() {
            return NO_BYTES;
        }

        public int drain(final byte[] dst, final int offs, final int len) {
            return 0;
        }
    };

    abstract class Base64EncodingCodePointIterator extends CodePointIterator {

        private final boolean addPadding;
        private int c0, c1, c2, c3;
        private int state;
        private int offset;

        public Base64EncodingCodePointIterator(final boolean addPadding) {
            this.addPadding = addPadding;
        }

        // states:
        // 0 - need another three data bytes
        // 1 - 4 characters to read
        // 2 - 3 characters to read
        // 3 - 2 characters to read
        // 4 - 1 character to read
        // 5 - 2 characters + == to read
        // 6 - 1 character (c1) + == to read
        // 7 - == to read
        // 8 - second = to read
        // 9 - 3 characters + = to read
        // a - 2 characters (c1, c2) + = to read
        // b - 1 character (c2) + = to read
        // c - = to read
        // d - after ==
        // e - after =
        // f - clean end

        public boolean hasNext() {
            return state == 0 && ByteIterator.this.hasNext() || state > 0 && state < 0xd;
        }

        public boolean hasPrev() {
            return offset > 0;
        }

        abstract int calc0(int b0);

        abstract int calc1(int b0, int b1);

        abstract int calc2(int b1, int b2);

        abstract int calc3(int b2);

        public int next() throws NoSuchElementException {
            if (! hasNext()) throw new NoSuchElementException();
            offset++;
            switch (state) {
                case 0: {
                    assert ByteIterator.this.hasNext();
                    int b0 = ByteIterator.this.next();
                    c0 = calc0(b0);
                    if (!ByteIterator.this.hasNext()) {
                        c1 = calc1(b0, 0);
                        state = 6;
                        return c0;
                    }
                    int b1 = ByteIterator.this.next();
                    c1 = calc1(b0, b1);
                    if (!ByteIterator.this.hasNext()) {
                        c2 = calc2(b1, 0);
                        state = 0xa;
                        return c0;
                    }
                    int b2 = ByteIterator.this.next();
                    c2 = calc2(b1, b2);
                    c3 = calc3(b2);
                    state = 2;
                    return c0;
                }
                case 1: {
                    state = 2;
                    return c0;
                }
                case 2: {
                    state = 3;
                    return c1;
                }
                case 3: {
                    state = 4;
                    return c2;
                }
                case 4: {
                    state = 0;
                    return c3;
                }
                case 5: {
                    state = 6;
                    return c0;
                }
                case 6: {
                    state = addPadding ? 7 : 0xd;
                    return c1;
                }
                case 7: {
                    state = 8;
                    return '=';
                }
                case 8: {
                    state = 0xd;
                    return '=';
                }
                case 9: {
                    state = 0xa;
                    return c0;
                }
                case 0xa: {
                    state = 0xb;
                    return c1;
                }
                case 0xb: {
                    state = addPadding ? 0xc : 0xe;
                    return c2;
                }
                case 0xc: {
                    state = 0xe;
                    return '=';
                }
                default: {
                    throw new IllegalStateException();
                }
            }
        }

        public int peekNext() throws NoSuchElementException {
            if (! hasNext()) throw new NoSuchElementException();
            switch (state) {
                case 0: {
                    assert ByteIterator.this.hasNext();
                    int b0 = ByteIterator.this.next();
                    c0 = calc0(b0);
                    if (!ByteIterator.this.hasNext()) {
                        c1 = calc1(b0, 0);
                        state = 5;
                        return c0;
                    }
                    int b1 = ByteIterator.this.next();
                    c1 = calc1(b0, b1);
                    if (!ByteIterator.this.hasNext()) {
                        c2 = calc2(b1, 0);
                        state = 9;
                        return c0;
                    }
                    int b2 = ByteIterator.this.next();
                    c2 = calc2(b1, b2);
                    c3 = calc3(b2);
                    state = 1;
                    return c0;
                }
                case 1: {
                    return c0;
                }
                case 2: {
                    return c1;
                }
                case 3: {
                    return c2;
                }
                case 4: {
                    return c3;
                }
                case 5: {
                    return c0;
                }
                case 6: {
                    return c1;
                }
                case 7: {
                    return '=';
                }
                case 8: {
                    return '=';
                }
                case 9: {
                    return c0;
                }
                case 0xa: {
                    return c1;
                }
                case 0xb: {
                    return c2;
                }
                case 0xc: {
                    return '=';
                }
                default: {
                    throw new IllegalStateException();
                }
            }
        }

        public int prev() throws NoSuchElementException {
            if (! hasPrev()) throw new NoSuchElementException();
            offset--;
            switch (state) {
                case 0:
                case 1:
                case 5:
                case 9:
                case 0xf: {
                    int b2 = ByteIterator.this.prev();
                    int b1 = ByteIterator.this.prev();
                    int b0 = ByteIterator.this.prev();
                    c0 = calc0(b0);
                    c1 = calc1(b0, b1);
                    c2 = calc2(b1, b2);
                    c3 = calc3(b2);
                    state = 4;
                    return c3;
                }
                case 2: {
                    state = 1;
                    return c0;
                }
                case 3: {
                    state = 2;
                    return c1;
                }
                case 4: {
                    state = 3;
                    return c2;
                }
                case 6: {
                    state = 5;
                    return c0;
                }
                case 7: {
                    state = 6;
                    return c1;
                }
                case 8: {
                    state = 7;
                    return '=';
                }
                case 0xa: {
                    state = 9;
                    return c0;
                }
                case 0xb: {
                    state = 0xa;
                    return c1;
                }
                case 0xc: {
                    state = 0xb;
                    return c2;
                }
                case 0xd: {
                    state = 8;
                    return '=';
                }
                case 0xe: {
                    state = 0xc;
                    return '=';
                }
                default: throw new IllegalStateException();
            }
        }

        public int peekPrev() throws NoSuchElementException {
            if (! hasPrev()) throw new NoSuchElementException();
            switch (state) {
                case 0:
                case 1:
                case 5:
                case 9:
                case 0xf: {
                    return calc3(ByteIterator.this.peekPrev());
                }
                case 2: {
                    return c0;
                }
                case 3: {
                    return c1;
                }
                case 4: {
                    return c2;
                }
                case 6: {
                    return c0;
                }
                case 7: {
                    return c1;
                }
                case 8: {
                    return '=';
                }
                case 0xa: {
                    return c0;
                }
                case 0xb: {
                    return c1;
                }
                case 0xc: {
                    return c2;
                }
                case 0xd: {
                    return '=';
                }
                case 0xe: {
                    return '=';
                }
                default: throw new IllegalStateException();
            }
        }

        public int offset() {
            return offset;
        }
    }
}
