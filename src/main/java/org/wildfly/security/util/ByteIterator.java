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

import static org.wildfly.security.util.Alphabet.*;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
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
    public ByteIterator base64Decode(final Base64Alphabet alphabet, boolean requirePadding) {
        return super.base64Decode(alphabet, requirePadding);
    }

    /**
     * Base64-decode the current stream, assuming that the byte data is encoded in an ASCII-derived encoding.
     *
     * @param alphabet the alphabet to use
     * @return an iterator over the decoded bytes
     */
    public ByteIterator base64Decode(final Base64Alphabet alphabet) {
        return super.base64Decode(alphabet, true);
    }

    /**
     * Base64-decode the current stream, assuming that the byte data is encoded in an ASCII-derived encoding.
     *
     * @return an iterator over the decoded bytes
     */
    public ByteIterator base64Decode() {
        return super.base64Decode(Base64Alphabet.STANDARD, true);
    }

    /**
     * Base64-encode the current stream.
     *
     * @param alphabet the alphabet to use
     * @param addPadding {@code true} to add trailing padding, {@code false} to leave it off
     * @return an iterator over the encoded characters
     */
    public CodePointIterator base64Encode(final Base64Alphabet alphabet, final boolean addPadding) {
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
    public CodePointIterator base64Encode(final Base64Alphabet alphabet) {
        return base64Encode(alphabet, true);
    }

    /**
     * Base64-encode the current stream.
     *
     * @return an iterator over the encoded characters
     */
    public CodePointIterator base64Encode() {
        return base64Encode(Base64Alphabet.STANDARD, true);
    }

    /**
     * Base32-decode the current stream, assuming that the byte data is encoded in an ASCII-derived encoding.
     *
     * @param alphabet the alphabet to use
     * @param requirePadding {@code true} to require padding, {@code false} if padding is optional
     * @return an iterator over the decoded bytes
     */
    public ByteIterator base32Decode(final Base32Alphabet alphabet, boolean requirePadding) {
        return super.base32Decode(alphabet, requirePadding);
    }

    /**
     * Base32-decode the current stream, assuming that the byte data is encoded in an ASCII-derived encoding.
     *
     * @param alphabet the alphabet to use
     * @return an iterator over the decoded bytes
     */
    public ByteIterator base32Decode(final Base32Alphabet alphabet) {
        return super.base32Decode(alphabet, true);
    }

    /**
     * Base32-decode the current stream, assuming that the byte data is encoded in an ASCII-derived encoding.
     *
     * @return an iterator over the decoded bytes
     */
    public ByteIterator base32Decode() {
        return super.base32Decode(Base32Alphabet.STANDARD, true);
    }

    /**
     * Base32-encode the current stream.
     *
     * @param alphabet the alphabet to use
     * @param addPadding {@code true} to add trailing padding, {@code false} to leave it off
     * @return an iterator over the encoded characters
     */
    public CodePointIterator base32Encode(final Base32Alphabet alphabet, final boolean addPadding) {
        if (alphabet.littleEndian) {
            return new Base32EncodingCodePointIterator(addPadding) {
                int calc0(final int b0) {
                    // d0 = r0[4..0]
                    return alphabet.encode(b0 & 0x1f);
                }

                int calc1(final int b0, final int b1) {
                    // d1 = r1[1..0] + r0[7..5]
                    return alphabet.encode((b1 << 3 | b0 >> 5) & 0x1f);
                }

                int calc2(final int b1) {
                    // d2 = r1[6..2]
                    return alphabet.encode((b1 >> 2) & 0x1f);
                }

                int calc3(final int b1, final int b2) {
                    // d3 = r2[3..0] + r1[7]
                    return alphabet.encode((b2 << 1 | b1 >> 7) & 0x1f);
                }

                int calc4(final int b2, final int b3) {
                    // d4 = r3[0] + r2[7..4]
                    return alphabet.encode((b3 << 4 | b2 >> 4) & 0x1f);
                }

                int calc5(final int b3) {
                    // d5 = r3[5..1]
                    return alphabet.encode((b3 >> 1) & 0x1f);
                }

                int calc6(final int b3, final int b4) {
                    // d6 = r4[2..0] + r3[7..6]
                    return alphabet.encode((b4 << 2 | b3 >> 6) & 0x1f);
                }

                int calc7(final int b4) {
                    // d7 = r4[7..3]
                    return alphabet.encode((b4 >> 3) & 0x1f);
                }
            };
        } else {
            return new Base32EncodingCodePointIterator(addPadding) {
                int calc0(final int b0) {
                    // d0 = r0[7..3]
                    return alphabet.encode((b0 >> 3) & 0x1f);
                }

                int calc1(final int b0, final int b1) {
                    // d1 = r0[2..0] + r1[7..6]
                    return alphabet.encode((b0 << 2 | b1 >> 6) & 0x1f);
                }

                int calc2(final int b1) {
                    // d2 = r1[5..1]
                    return alphabet.encode((b1 >> 1) & 0x1f);
                }

                int calc3(final int b1, final int b2) {
                    // d3 = r1[0] + r2[7..4]
                    return alphabet.encode((b1 << 4 | b2 >> 4) & 0x1f);
                }

                int calc4(final int b2, final int b3) {
                    // d4 = r2[3..0] + r3[7]
                    return alphabet.encode((b2 << 1 | b3 >> 7) & 0x1f);
                }

                int calc5(final int b3) {
                    // d5 = r3[6..2]
                    return alphabet.encode((b3 >> 2) & 0x1f);
                }

                int calc6(final int b3, final int b4) {
                    // d6 = r3[1..0] + r4[7..5]
                    return alphabet.encode((b3 << 3 | b4 >> 5) & 0x1f);
                }

                int calc7(final int b4) {
                    // d7 = r4[4..0]
                    return alphabet.encode(b4 & 0x1f);
                }
            };
        }
    }

    /**
     * Base32-encode the current stream.
     *
     * @param alphabet the alphabet to use
     * @return an iterator over the encoded characters
     */
    public CodePointIterator base32Encode(final Base32Alphabet alphabet) {
        return base32Encode(alphabet, true);
    }

    /**
     * Base32-encode the current stream.
     *
     * @return an iterator over the encoded characters
     */
    public CodePointIterator base32Encode() {
        return base32Encode(Base32Alphabet.STANDARD, true);
    }

    /**
     * Hex-decode the current stream, assuming that the byte data is encoded in an ASCII-derived encoding.
     *
     * @return an iterator over the decoded bytes
     */
    public ByteIterator hexDecode() {
        return super.hexDecode();
    }

    /**
     * Hex-encode the current stream.
     *
     * @param toUpperCase {@code true} to use upper case characters when encoding,
     * {@code false} to use lower case characters
     * @return an iterator over the encoded characters
     */
    public CodePointIterator hexEncode(boolean toUpperCase) {
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
                if (i < 10) {
                    return '0' + i;
                } else {
                    assert i < 16;
                    return (toUpperCase ? 'A' : 'a') + i - 10;
                }
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
     * Hex-encode the current stream.
     *
     * @return an iterator over the encoded characters
     */
    public CodePointIterator hexEncode() {
        return hexEncode(false);
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
     * Get a sub-iterator that is delimited by the given bytes.  The returned iterator offset starts at 0 and cannot
     * be backed up before that point.  The returned iterator will return {@code false} for {@code hasNext()} if the next
     * character in the encapsulated iterator is a delimiter or if the underlying iterator returns {@code false} for
     * {@code hasNext()}.
     *
     * @param delims the byte delimiters
     * @return the sub-iterator
     */
    public final ByteIterator delimitedBy(final int... delims) {
        if ((delims == null) || (delims.length == 0) || ! hasNext()) {
            return EMPTY;
        }
        for (int delim : delims) {
            if (delim < 0 || delim > 0xff) {
                return EMPTY;
            }
        }
        return new ByteIterator() {
            int offset = 0;
            int current = -1;

            public boolean hasNext() {
                return ByteIterator.this.hasNext() && ! isDelim(ByteIterator.this.peekNext());
            }

            public boolean hasPrev() {
                return offset > 0;
            }

            public int next() {
                int n = ByteIterator.this.peekNext();
                if (isDelim(n)) {
                    current = -1;
                    throw new NoSuchElementException();
                }
                offset ++;
                return current = ByteIterator.this.next();
            }

            public int peekNext() throws NoSuchElementException {
                int n = ByteIterator.this.peekNext();
                if (isDelim(n)) {
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

            private boolean isDelim(int b) {
                for (int delim : delims) {
                    if (delim == b) {
                        return true;
                    }
                }
                return false;
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

    public final InputStream asInputStream() {
        return new InputStream() {
            public int read() throws IOException {
                return hasNext() ? next() : -1;
            }

            public int read(final byte[] b) throws IOException {
                return drain(b);
            }

            public int read(final byte[] b, final int off, final int len) throws IOException {
                return drain(b, off, len);
            }
        };
    }

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

    abstract class Base32EncodingCodePointIterator extends CodePointIterator {

        private final boolean addPadding;
        private int c0, c1, c2, c3, c4, c5, c6, c7;
        private int state;
        private int offset;

        public Base32EncodingCodePointIterator(final boolean addPadding) {
            this.addPadding = addPadding;
        }

        // states:
        // 0x00 - need another five data bytes
        // 0x01 - 8 characters to read
        // 0x02 - 7 characters to read
        // 0x03 - 6 characters to read
        // 0x04 - 5 characters to read
        // 0x05 - 4 characters to read
        // 0x06 - 3 characters to read
        // 0x07 - 2 characters to read
        // 0x08 - 1 character to read
        // 0x09 - 2 characters + ====== to read
        // 0x0a - 1 character (c1) + ====== to read
        // 0x0b - ====== to read
        // 0x0c - ===== to read
        // 0x0d - ==== to read
        // 0x0e - === to read
        // 0x0f - == to read
        // 0x10 - = to read
        // 0x11 - 4 characters + ==== to read
        // 0x12 - 3 characters (c1, c2, c3) + ==== to read
        // 0x13 - 2 characters (c2, c3) + ==== to read
        // 0x14 - 1 character (c3) + ==== to read
        // 0x15 - ==== to read
        // 0x16 - === to read
        // 0x17 - == to read
        // 0x18 - = to read
        // 0x19 - 5 characters + === to read
        // 0x1a - 4 characters (c1, c2, c3, c4) + === to read
        // 0x1b - 3 characters (c2, c3, c4) + === to read
        // 0x1c - 2 characters (c3, c4) + === to read
        // 0x1d - 1 character (c4) + === to read
        // 0x1e - === to read
        // 0x1f - == to read
        // 0x20 - = to read
        // 0x21 - 7 characters + = to read
        // 0x22 - 6 characters (c1, c2, c3, c4, c5, c6) + = to read
        // 0x23 - 5 characters (c2, c3, c4, c5, c6) + = to read
        // 0x24 - 4 characters (c3, c4, c5, c6) + = to read
        // 0x25 - 3 characters (c4, c5, c6) + = to read
        // 0x26 - 2 characters (c5, c6) + = to read
        // 0x27 - 1 characters (c6) + = to read
        // 0x28 - = to read
        // 0x29 - after ======
        // 0x2a - after ====
        // 0x2b - after ===
        // 0x2c - after =
        // 0x2d - end

        public boolean hasNext() {
            return state == 0 && ByteIterator.this.hasNext() || state > 0 && state < 0x29;
        }

        public boolean hasPrev() {
            return offset > 0;
        }

        abstract int calc0(int b0);

        abstract int calc1(int b0, int b1);

        abstract int calc2(final int b1);

        abstract int calc3(final int b1, final int b2);

        abstract int calc4(final int b2, final int b3);

        abstract int calc5(final int b3);

        abstract int calc6(final int b3, final int b4);

        abstract int calc7(final int b4);

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
                        state = 0x0a;
                        return c0;
                    }
                    int b1 = ByteIterator.this.next();
                    c1 = calc1(b0, b1);
                    c2 = calc2(b1);
                    if (!ByteIterator.this.hasNext()) {
                        c3 = calc3(b1, 0);
                        state = 0x12;
                        return c0;
                    }
                    int b2 = ByteIterator.this.next();
                    c3 = calc3(b1, b2);
                    if (!ByteIterator.this.hasNext()) {
                        c4 = calc4(b2, 0);
                        state = 0x1a;
                        return c0;
                    }
                    int b3 = ByteIterator.this.next();
                    c4 = calc4(b2, b3);
                    c5 = calc5(b3);
                    if (!ByteIterator.this.hasNext()) {
                        c6 = calc6(b3, 0);
                        state = 0x22;
                        return c0;
                    }
                    int b4 = ByteIterator.this.next();
                    c6 = calc6(b3, b4);
                    c7 = calc7(b4);
                    state = 2;
                    return c0;
                }
                case 1:
                case 9:
                case 0x11:
                case 0x19:
                case 0x21: {
                    state ++;
                    return c0;
                }
                case 2:
                case 0x12:
                case 0x1a:
                case 0x22: {
                    state ++;
                    return c1;
                }
                case 3:
                case 0x13:
                case 0x1b:
                case 0x23: {
                    state ++;
                    return c2;
                }
                case 4:
                case 0x1c:
                case 0x24: {
                    state ++;
                    return c3;
                }
                case 5:
                case 0x25: {
                    state ++;
                    return c4;
                }
                case 6:
                case 0x26: {
                    state ++;
                    return c5;
                }
                case 7: {
                    state = 8;
                    return c6;
                }
                case 8: {
                    state = 0;
                    return c7;
                }
                case 0x0a: {
                    state = addPadding ? 0x0b : 0x29;
                    return c1;
                }
                case 0x14: {
                    state = addPadding ? 0x15 : 0x2a;
                    return c3;
                }
                case 0x1d: {
                    state = addPadding ? 0x1e : 0x2b;
                    return c4;
                }
                case 0x27: {
                    state = addPadding ? 0x28 : 0x2c;
                    return c6;
                }
                case 0x0b:
                case 0x0c:
                case 0x0d:
                case 0x0e:
                case 0x0f:
                case 0x15:
                case 0x16:
                case 0x17:
                case 0x1e:
                case 0x1f: {
                    state ++;
                    return '=';
                }
                case 0x10: {
                    state = 0x29;
                    return '=';
                }
                case 0x18: {
                    state = 0x2a;
                    return '=';
                }
                case 0x20: {
                    state = 0x2b;
                    return '=';
                }
                case 0x28: {
                    state = 0x2c;
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
                        state = 9;
                        return c0;
                    }
                    int b1 = ByteIterator.this.next();
                    c1 = calc1(b0, b1);
                    c2 = calc2(b1);
                    if (!ByteIterator.this.hasNext()) {
                        c3 = calc3(b1, 0);
                        state = 0x11;
                        return c0;
                    }
                    int b2 = ByteIterator.this.next();
                    c3 = calc3(b1, b2);
                    if (!ByteIterator.this.hasNext()) {
                        c4 = calc4(b2, 0);
                        state = 0x19;
                        return c0;
                    }
                    int b3 = ByteIterator.this.next();
                    c4 = calc4(b2, b3);
                    c5 = calc5(b3);
                    if (!ByteIterator.this.hasNext()) {
                        c6 = calc6(b3, 0);
                        state = 0x21;
                        return c0;
                    }
                    int b4 = ByteIterator.this.next();
                    c6 = calc6(b3, b4);
                    c7 = calc7(b4);
                    state = 1;
                    return c0;
                }
                case 1:
                case 9:
                case 0x11:
                case 0x19:
                case 0x21: {
                    return c0;
                }
                case 2:
                case 0x0a:
                case 0x12:
                case 0x1a:
                case 0x22: {
                    return c1;
                }
                case 3:
                case 0x13:
                case 0x1b:
                case 0x23: {
                    return c2;
                }
                case 4:
                case 0x14:
                case 0x1c:
                case 0x24: {
                    return c3;
                }
                case 5:
                case 0x1d:
                case 0x25: {
                    return c4;
                }
                case 6:
                case 0x26: {
                    return c5;
                }
                case 7:
                case 0x27: {
                    return c6;
                }
                case 8: {
                    return c7;
                }
                case 0x0b:
                case 0x0c:
                case 0x0d:
                case 0x0e:
                case 0x0f:
                case 0x10:
                case 0x15:
                case 0x16:
                case 0x17:
                case 0x18:
                case 0x1e:
                case 0x1f:
                case 0x20:
                case 0x28: {
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
                case 0x21: {
                    ByteIterator.this.prev(); // skip and fall through
                }
                case 0x19: {
                    ByteIterator.this.prev(); // skip and fall through
                }
                case 0x11: {
                    ByteIterator.this.prev(); // skip and fall through
                }
                case 9: {
                    ByteIterator.this.prev(); // skip and fall through
                }
                case 0:
                case 1:
                case 0x2d: {
                    int b4 = ByteIterator.this.prev();
                    int b3 = ByteIterator.this.prev();
                    int b2 = ByteIterator.this.prev();
                    int b1 = ByteIterator.this.prev();
                    int b0 = ByteIterator.this.prev();
                    c0 = calc0(b0);
                    c1 = calc1(b0, b1);
                    c2 = calc2(b1);
                    c3 = calc3(b1, b2);
                    c4 = calc4(b2, b3);
                    c5 = calc5(b3);
                    c6 = calc6(b3, b4);
                    c7 = calc7(b4);
                    state = 8;
                    return c7;
                }
                case 2:
                case 0x0a:
                case 0x1a:
                case 0x12:
                case 0x22: {
                    state --;
                    return c0;
                }
                case 3:
                case 0x0b:
                case 0x13:
                case 0x1b:
                case 0x23: {
                    state --;
                    return c1;
                }
                case 4:
                case 0x14:
                case 0x1c:
                case 0x24: {
                    state --;
                    return c2;
                }
                case 5:
                case 0x15:
                case 0x1d:
                case 0x25: {
                    state --;
                    return c3;
                }
                case 6:
                case 0x1e:
                case 0x26: {
                    state --;
                    return c4;
                }
                case 7:
                case 0x27: {
                    state --;
                    return c5;
                }
                case 8:
                case 0x28: {
                    state --;
                    return c6;
                }
                case 0x0c:
                case 0x0d:
                case 0x0e:
                case 0x0f:
                case 0x10:
                case 0x16:
                case 0x17:
                case 0x18:
                case 0x1f:
                case 0x20: {
                    state --;
                    return '=';
                }
                case 0x29: {
                    if (addPadding) {
                        state = 0x10;
                        return '=';
                    } else {
                        state = 0x0a;
                        return c1;
                    }
                }
                case 0x2a: {
                    if (addPadding) {
                        state = 0x18;
                        return '=';
                    } else {
                        state = 0x14;
                        return c3;
                    }
                }
                case 0x2b: {
                    if (addPadding) {
                        state = 0x20;
                        return '=';
                    } else {
                        state = 0x1d;
                        return c4;
                    }
                }
                case 0x2c: {
                    if (addPadding) {
                        state = 0x28;
                        return '=';
                    } else {
                        state = 0x27;
                        return c6;
                    }
                }
                default: throw new IllegalStateException();
            }
        }

        public int peekPrev() throws NoSuchElementException {
            if (! hasPrev()) throw new NoSuchElementException();
            switch (state) {
                case 0x21:
                    ByteIterator.this.prev(); // skip and fall through
                case 0x19:
                    ByteIterator.this.prev(); // skip and fall through
                case 0x11:
                    ByteIterator.this.prev(); // skip and fall through
                case 9:
                    ByteIterator.this.prev(); // skip and fall through
                case 0:
                case 1:
                case 0x2d: {
                    int result = calc7(ByteIterator.this.peekPrev());
                    if (state == 9) {
                        ByteIterator.this.next();
                    } else if (state == 0x11) {
                        ByteIterator.this.next();
                        ByteIterator.this.next();
                    } else if (state == 0x19) {
                        ByteIterator.this.next();
                        ByteIterator.this.next();
                        ByteIterator.this.next();
                    } else if (state == 0x21) {
                        ByteIterator.this.next();
                        ByteIterator.this.next();
                        ByteIterator.this.next();
                        ByteIterator.this.next();
                    }
                    return result;
                }
                case 2:
                case 0x0a:
                case 0x1a:
                case 0x12:
                case 0x22: {
                    return c0;
                }
                case 3:
                case 0x0b:
                case 0x13:
                case 0x1b:
                case 0x23: {
                    return c1;
                }
                case 4:
                case 0x14:
                case 0x1c:
                case 0x24: {
                    return c2;
                }
                case 5:
                case 0x15:
                case 0x1d:
                case 0x25: {
                    return c3;
                }
                case 6:
                case 0x1e:
                case 0x26: {
                    return c4;
                }
                case 7:
                case 0x27: {
                    return c5;
                }
                case 8:
                case 0x28: {
                    return c6;
                }
                case 0x0c:
                case 0x0d:
                case 0x0e:
                case 0x0f:
                case 0x10:
                case 0x16:
                case 0x17:
                case 0x18:
                case 0x1f:
                case 0x20: {
                    return '=';
                }
                case 0x29: {
                    return addPadding ? '=' : c1;
                }
                case 0x2a: {
                    return addPadding ? '=' : c3;
                }
                case 0x2b: {
                    return addPadding ? '=' : c4;
                }
                case 0x2c: {
                    return addPadding ? '=' : c6;
                }
                default: throw new IllegalStateException();
            }
        }

        public int offset() {
            return offset;
        }
    }
}
