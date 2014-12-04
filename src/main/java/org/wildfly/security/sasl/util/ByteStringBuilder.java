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

package org.wildfly.security.sasl.util;

import java.security.DigestException;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.NoSuchElementException;

import javax.crypto.Mac;

import org.wildfly.security.util.ByteIterator;
import org.wildfly.security.util.CodePointIterator;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class ByteStringBuilder {
    private byte[] content;
    private int length;

    public ByteStringBuilder() {
        this.content = new byte[16];
    }

    public ByteStringBuilder(final byte[] content) {
        this.content = content.clone();
        this.length = this.content.length;
    }

    public ByteStringBuilder append(boolean b) {
        appendLatin1(Boolean.toString(b));
        return this;
    }

    public ByteStringBuilder append(byte b) {
        doAppend(b);
        return this;
    }

    public ByteStringBuilder append(char c) {
        return appendUtf8Raw((int) c);
    }

    public ByteStringBuilder appendUtf8Raw(int codePoint) {
        if (codePoint < 0) {
            throw new IllegalArgumentException();
        } else if (codePoint < 0x80) {
            doAppend((byte) codePoint);
        } else if (codePoint < 0x800) {
            doAppend((byte) (0xC0 | 0x1F & codePoint >>> 6));
            doAppend((byte) (0x80 | 0x3F & codePoint));
        } else if (codePoint < 0x10000) {
            doAppend((byte) (0xE0 | 0x0F & codePoint >>> 12));
            doAppend((byte) (0x80 | 0x3F & codePoint >>> 6));
            doAppend((byte) (0x80 | 0x3F & codePoint));
        } else if (codePoint < 0x110000) {
            doAppend((byte) (0xF0 | 0x07 & codePoint >>> 18));
            doAppend((byte) (0x80 | 0x3F & codePoint >>> 12));
            doAppend((byte) (0x80 | 0x3F & codePoint >>> 6));
            doAppend((byte) (0x80 | 0x3F & codePoint));
        } else {
            throw new IllegalArgumentException();
        }
        return this;
    }

    public ByteStringBuilder appendUtf8(CodePointIterator iterator) {
        while (iterator.hasNext()) {
            appendUtf8Raw(iterator.next());
        }
        return this;
    }

    public ByteStringBuilder appendLatin1(CodePointIterator iterator) {
        int cp;
        while (iterator.hasNext()) {
            cp = iterator.next();
            if (cp > 255) throw new IllegalArgumentException();
            append((byte) cp);
        }
        return this;
    }

    public ByteStringBuilder appendAscii(CodePointIterator iterator) {
        int cp;
        while (iterator.hasNext()) {
            cp = iterator.next();
            if (cp > 127) throw new IllegalArgumentException();
            append((byte) cp);
        }
        return this;
    }

    public ByteStringBuilder append(ByteIterator iterator) {
        return iterator.appendTo(this);
    }

    public ByteStringBuilder append(byte[] bytes) {
        int length = this.length;
        int bl = bytes.length;
        reserve(bl, false);
        System.arraycopy(bytes, 0, content, length, bl);
        this.length = length + bl;
        return this;
    }

    public ByteStringBuilder append(byte[] bytes, int offs, int len) {
        reserve(len, false);
        int length = this.length;
        System.arraycopy(bytes, offs, content, length, len);
        this.length = length + len;
        return this;
    }

    public ByteStringBuilder appendLatin1(CharSequence s) {
        int len = s.length();
        reserve(len, false);
        char c;
        for (int i = 0; i < len; i ++) {
            c = s.charAt(i);
            if (c > 255) throw new IllegalArgumentException();
            doAppendNoCheck((byte) c);
        }
        return this;
    }

    public ByteStringBuilder appendLatin1(CharSequence s, int offs, int len) {
        reserve(len, false);
        char c;
        for (int i = 0; i < len; i ++) {
            c = s.charAt(i + offs);
            if (c > 255) throw new IllegalArgumentException();
            doAppendNoCheck((byte) c);
        }
        return this;
    }

    public ByteStringBuilder appendLatin1(String s) {
        int len = s.length();
        reserve(len, false);
        char c;
        for (int i = 0; i < len; i ++) {
            c = s.charAt(i);
            if (c > 255) throw new IllegalArgumentException();
            doAppendNoCheck((byte) c);
        }
        return this;
    }

    public ByteStringBuilder appendLatin1(String s, int offs, int len) {
        reserve(len, false);
        char c;
        for (int i = 0; i < len; i ++) {
            c = s.charAt(i + offs);
            if (c > 255) throw new IllegalArgumentException();
            doAppendNoCheck((byte) c);
        }
        return this;
    }

    public ByteStringBuilder append(CharSequence s) {
        return append(s, 0, s.length());
    }

    public ByteStringBuilder append(CharSequence s, int offs, int len) {
        int c;
        int i = 0;
        while (i < len) {
            c = s.charAt(offs + i++);
            if (Character.isHighSurrogate((char) c)) {
                if (i < len) {
                    char t = s.charAt(offs + i ++);
                    if (! Character.isLowSurrogate(t)) {
                        throw new IllegalArgumentException();
                    }
                    c = Character.toCodePoint((char) c, t);
                } else {
                    throw new IllegalArgumentException();
                }
            }
            appendUtf8Raw(c);
        }
        return this;
    }

    public ByteStringBuilder append(String s) {
        return append(s, 0, s.length());
    }

    public ByteStringBuilder append(String s, int offs, int len) {
        int c;
        int i = 0;
        while (i < len) {
            c = s.charAt(offs + i++);
            if (Character.isHighSurrogate((char) c)) {
                if (i < len) {
                    char t = s.charAt(offs + i ++);
                    if (! Character.isLowSurrogate(t)) {
                        throw new IllegalArgumentException();
                    }
                    c = Character.toCodePoint((char) c, t);
                } else {
                    throw new IllegalArgumentException();
                }
            }
            appendUtf8Raw(c);
        }
        return this;
    }

    public ByteStringBuilder appendBE(short s) {
        doAppend((byte) (s >>> 8));
        doAppend((byte) s);
        return this;
    }

    public ByteStringBuilder appendNumber(int i) {
        appendLatin1(Integer.toString(i));
        return this;
    }

    public ByteStringBuilder appendBE(int i) {
        doAppend((byte) (i >>> 24));
        doAppend((byte) (i >>> 16));
        doAppend((byte) (i >>> 8));
        doAppend((byte) i);
        return this;
    }

    public ByteStringBuilder appendNumber(long l) {
        appendLatin1(Long.toString(l));
        return this;
    }

    public ByteStringBuilder appendBE(long l) {
        doAppend((byte) (l >>> 56));
        doAppend((byte) (l >>> 48));
        doAppend((byte) (l >>> 40));
        doAppend((byte) (l >>> 32));
        doAppend((byte) (l >>> 24));
        doAppend((byte) (l >>> 16));
        doAppend((byte) (l >>> 8));
        doAppend((byte) l);
        return this;
    }

    public ByteStringBuilder appendObject(Object o) {
        appendLatin1(String.valueOf(o));
        return this;
    }

    public ByteStringBuilder append(ByteStringBuilder other) {
        append(other.content, 0, other.length);
        return this;
    }

    public ByteStringBuilder updateDigest(final MessageDigest messageDigest) {
        messageDigest.update(content, 0, length);
        return this;
    }

    public ByteStringBuilder appendDigestResult(final MessageDigest messageDigest) throws DigestException {
        reserve(messageDigest.getDigestLength(), false);
        final int length = this.length;
        final byte[] content = this.content;
        this.length = length + messageDigest.digest(content, length, content.length - length);
        return this;
    }

    public ByteStringBuilder updateMac(final Mac mac) {
        mac.update(content, 0, length);
        return this;
    }

    public byte[] toArray() {
        return Arrays.copyOf(content, length);
    }

    public byte byteAt(int index) {
        if (index < 0 || index > length) throw new IndexOutOfBoundsException();
        return content[index];
    }

    public int capacity() {
        return content.length;
    }

    public int length() {
        return length;
    }

    public void setLength(int newLength) {
        if (newLength > length) {
            // grow
            reserve(newLength - length, true);
        }
        length = newLength;
    }

    public boolean contentEquals(final byte[] other) {
        return contentEquals(other, 0, other.length);
    }

    public boolean contentEquals(final byte[] other, final int offs, final int length) {
        if (length != this.length) return false;
        for (int i = 0; i < length; i++) {
            if (content[i] != other[offs + i]) {
                return false;
            }
        }
        return true;
    }

    private void reserve(final int count, final boolean clear) {
        final int length = this.length;
        final byte[] content = this.content;
        int cl = content.length;
        if (cl - length >= count) {
            if (clear) Arrays.fill(content, length, length + count, (byte) 0);
            return;
        }
        // clear remainder
        if (clear) Arrays.fill(content, length, cl, (byte) 0);
        do {
            // not enough space... grow by 1.5x
            cl = cl + (cl + 1 >> 1);
            if (cl < 0) throw new IllegalStateException("Too large");
        } while (cl - length < count);
        this.content = Arrays.copyOf(content, cl);
    }

    private void doAppend(final byte b) {
        byte[] content = this.content;
        final int cl = content.length;
        final int length = this.length;
        if (length == cl) {
            content = this.content = Arrays.copyOf(content, cl + (cl + 1 >> 1));
        }
        content[length] = b;
        this.length = length + 1;
    }

    private void doAppendNoCheck(final byte b) {
        content[length ++] = b;
    }

    public ByteIterator iterate() {
        return new ByteIterator() {
            int idx = 0;

            public boolean hasNext() {
                return idx < length;
            }

            public boolean hasPrev() {
                return idx > 0;
            }

            public int next() throws NoSuchElementException {
                if (! hasNext()) throw new NoSuchElementException();
                return content[idx ++];
            }

            public int peekNext() throws NoSuchElementException {
                if (! hasNext()) throw new NoSuchElementException();
                return content[idx];
            }

            public int prev() throws NoSuchElementException {
                if (! hasPrev()) throw new NoSuchElementException();
                return content[--idx];
            }

            public int peekPrev() throws NoSuchElementException {
                if (! hasPrev()) throw new NoSuchElementException();
                return content[idx - 1];
            }

            public int offset() {
                return idx;
            }
        };
    }
}
