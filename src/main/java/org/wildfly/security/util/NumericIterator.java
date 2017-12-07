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

import static org.wildfly.security._private.ElytronMessages.log;
import static org.wildfly.security.util.Alphabet.*;

import java.util.NoSuchElementException;

/**
 * Non-public numeric iterator base class.  It is important to keep this non-public to prevent type confusion between
 * byte and code point iterators, which are fundamentally incompatible.
 *
 * @deprecated
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
@Deprecated
abstract class NumericIterator {

    public abstract boolean hasNext();

    public abstract boolean hasPrev();

    public abstract int next() throws NoSuchElementException;

    public abstract int peekNext() throws NoSuchElementException;

    public abstract int prev() throws NoSuchElementException;

    public abstract int peekPrev() throws NoSuchElementException;

    abstract class Base64ByteIterator extends ByteIterator {
        private final boolean requirePadding;
        // states:
        // 0: nothing read
        // 1: three bytes to return o0..2
        // 2: two bytes to return o1..2 (o0 still populated)
        // 3: one byte to return o2 (o0..o1 still populated)
        // 4: two bytes then eof o0..1 =
        // 5: one bytes then eof o1 = (o0 still populated)
        // 6: one byte then eof o0 ==
        // 7: two bytes then eof o0..1 no pad
        // 8: one byte then eof o1 no pad (o0 still populated)
        // 9: one byte then eof o0 no pad
        // a: end (==) (o0 still populated)
        // b: end (=) (o0..o1 still populated)
        // c: end (== but no pad) (o0 still populated)
        // d: end (= but no pad) (o0..o1 still populated)
        private int state = 0;
        private int o0, o1, o2;
        private int offset;

        protected Base64ByteIterator(final boolean requirePadding) {
            this.requirePadding = requirePadding;
        }

        public boolean hasNext() {
            if (state == 0) {
                if (! NumericIterator.this.hasNext()) {
                    return false;
                }
                int b0 = NumericIterator.this.next();
                if (b0 == '=') {
                    throw log.unexpectedPadding();
                }
                if (! NumericIterator.this.hasNext()) {
                    if (requirePadding) {
                        throw log.expectedPadding();
                    } else {
                        throw log.incompleteDecode();
                    }
                }
                int b1 = NumericIterator.this.next();
                if (b1 == '=') {
                    throw log.unexpectedPadding();
                }
                o0 = calc0(b0, b1);
                if (! NumericIterator.this.hasNext()) {
                    if (requirePadding) {
                        log.expectedPadding();
                    }
                    state = 9;
                    return true;
                }
                int b2 = NumericIterator.this.next();
                if (b2 == '=') {
                    if (! NumericIterator.this.hasNext()) {
                        throw log.expectedTwoPaddingCharacters();
                    }
                    if (NumericIterator.this.next() != '=') {
                        throw log.expectedTwoPaddingCharacters();
                    }
                    state = 6;
                    return true;
                }
                o1 = calc1(b1, b2);
                if (! NumericIterator.this.hasNext()) {
                    if (requirePadding) {
                        log.expectedPadding();
                    }
                    state = 7;
                    return true;
                }
                int b3 = NumericIterator.this.next();
                if (b3 == '=') {
                    state = 4;
                    return true;
                }
                o2 = calc2(b2, b3);
                state = 1;
                return true;
            } else {
                return state < 0xa;
            }
        }

        public boolean hasPrev() {
            return state != 0 || offset > 0;
        }

        abstract int calc0(int b0, int b1);

        abstract int calc1(int b1, int b2);

        abstract int calc2(int b2, int b3);

        public int next() {
            if (! hasNext()) {
                throw new NoSuchElementException();
            }
            switch (state) {
                case 1: {
                    state = 2;
                    offset ++;
                    return o0;
                }
                case 2: {
                    state = 3;
                    offset ++;
                    return o1;
                }
                case 3: {
                    state = 0;
                    offset ++;
                    return o2;
                }
                case 4: {
                    state = 5;
                    offset ++;
                    return o0;
                }
                case 5: {
                    state = 0xb;
                    offset ++;
                    return o1;
                }
                case 6: {
                    state = 0xa;
                    offset ++;
                    return o0;
                }
                case 7: {
                    state = 8;
                    offset ++;
                    return o0;
                }
                case 8: {
                    state = 0xd;
                    offset ++;
                    return o1;
                }
                case 9: {
                    state = 0xc;
                    offset ++;
                    return o0;
                }
                default: {
                    // padding
                    throw new NoSuchElementException();
                }
            }
        }

        public int peekNext() throws NoSuchElementException {
            if (! hasNext()) {
                throw new NoSuchElementException();
            }
            switch (state) {
                case 1:
                case 4:
                case 6:
                case 7:
                case 9: {
                    return o0;
                }
                case 2:
                case 5:
                case 8: {
                    return o1;
                }
                case 3: {
                    return o2;
                }
                default: {
                    // padding
                    throw new NoSuchElementException();
                }
            }
        }

        public int prev() {
            if (! hasPrev()) {
                throw new NoSuchElementException();
            }
            switch (state) {
                case 6: {
                    NumericIterator.this.prev(); // skip =
                    // fall thru
                }
                case 4: {
                    NumericIterator.this.prev(); // skip =
                    // fall thru
                }
                case 0:
                case 1:
                case 7:
                case 9:
                {
                    int b3 = NumericIterator.this.prev();
                    int b2 = NumericIterator.this.prev();
                    int b1 = NumericIterator.this.prev();
                    int b0 = NumericIterator.this.prev();
                    o0 = calc0(b0, b1);
                    o1 = calc1(b1, b2);
                    state = 3;
                    offset --;
                    return o2 = calc2(b2, b3);
                }
                case 2: {
                    state = 1;
                    offset --;
                    return o0;
                }
                case 3: {
                    state = 2;
                    offset --;
                    return o1;
                }
                case 5: {
                    state = 4;
                    offset --;
                    return o0;
                }
                case 8: {
                    state = 7;
                    offset --;
                    return o0;
                }
                case 0xa: {
                    state = 6;
                    offset --;
                    return o0;
                }
                case 0xb: {
                    state = 5;
                    offset --;
                    return o1;
                }
                case 0xc: {
                    state = 9;
                    offset --;
                    return o0;
                }
                case 0xd: {
                    state = 8;
                    offset --;
                    return o1;
                }
                default: {
                    // padding
                    throw new NoSuchElementException();
                }
            }
        }

        public int peekPrev() throws NoSuchElementException {
            if (! hasPrev()) {
                throw new NoSuchElementException();
            }
            switch (state) {
                case 6: {
                    NumericIterator.this.prev(); // skip =
                    // fall thru
                }
                case 4: {
                    NumericIterator.this.prev(); // skip =
                    // fall thru
                }
                case 0:
                case 1:
                case 7:
                case 9:
                {
                    int b3 = NumericIterator.this.prev();
                    int b2 = NumericIterator.this.peekPrev();
                    NumericIterator.this.next();
                    if (state == 4) {
                        NumericIterator.this.next();
                    } else if (state == 6) {
                        NumericIterator.this.next();
                        NumericIterator.this.next();
                    }
                    return calc2(b2, b3);
                }
                case 2: {
                    return o0;
                }
                case 3: {
                    return o1;
                }
                case 5: {
                    return o0;
                }
                case 8: {
                    return o0;
                }
                case 0xa: {
                    return o0;
                }
                case 0xb: {
                    return o1;
                }
                case 0xc: {
                    return o0;
                }
                case 0xd: {
                    return o1;
                }
                default: {
                    // padding
                    throw new NoSuchElementException();
                }
            }
        }

        public int offset() {
            return offset;
        }
    }

    abstract class Base32ByteIterator extends ByteIterator {
        private final boolean requirePadding;

        // states:
        // 0x00: nothing read
        // 0x01: five bytes to return o0..o4
        // 0x02: four bytes to return o1..o4 (o0 still populated)
        // 0x03: three byte to return o2..o4 (o0..o1 still populated)
        // 0x04: two bytes to return o3..o4 (o0..o2 still populated)
        // 0x05: one byte to return o4 (o0..o3 still populated)
        // 0x06: four bytes then eof o0..o3 =
        // 0x07: three bytes then eof o1..o3 = (o0 still populated)
        // 0x08: two bytes then eof o2..o3 = (o0..o1 still populated)
        // 0x09: one byte then eof o3 = (o0..o2 still populated)
        // 0x0a: three bytes then eof o0..o2 ===
        // 0x0b: two bytes then eof o1..o2 === (o0 still populated)
        // 0x0c: one byte then eof o2 === (o0..o1 still populated)
        // 0x0d: two bytes then eof o0..o1 ====
        // 0x0e: one byte then eof o1 ==== (o0 still populated)
        // 0x0f: one byte then eof o0 ======
        // 0x10: four bytes then eof o0..o3 no pad
        // 0x11: three bytes then eof o1..o3 no pad (o0 still populated)
        // 0x12: two bytes then eof o2..o3 no pad (o0..o1 still populated)
        // 0x13: one byte then eof o3 no pad (o0..o2 still populated)
        // 0x14: three bytes then eof o0..o2 no pad
        // 0x15: two bytes then eof o1..o2 no pad (o0 still populated)
        // 0x16: one byte then eof o2 no pad (o0..o1 still populated)
        // 0x17: two bytes then eof o0..o1 no pad
        // 0x18: one byte then eof o1 no pad (o0 still populated)
        // 0x19: one byte then eof o0 no pad
        // 0x1a: end (=) (o0..o3 still populated)
        // 0x1b: end (===) (o0..o2 still populated)
        // 0x1c: end (====) (o0..o1 still populated)
        // 0x1d: end (======) (o0 still populated)
        // 0x1e: end (= but no pad) (o0..o3 still populated)
        // 0x1f: end (=== but no pad) (o0..o2 still populated)
        // 0x20: end (==== but no pad) (o0..o1 still populated)
        // 0x21: end (====== but no pad) (o0 still populated)

        private int state = 0;
        private int o0, o1, o2, o3, o4;
        private int offset;

        protected Base32ByteIterator(final boolean requirePadding) {
            this.requirePadding = requirePadding;
        }

        public boolean hasNext() {
            if (state == 0) {
                if (! NumericIterator.this.hasNext()) {
                    return false;
                }
                int b0 = NumericIterator.this.next();
                if (b0 == '=') {
                    throw log.unexpectedPadding();
                }
                if (! NumericIterator.this.hasNext()) {
                    if (requirePadding) {
                        throw log.expectedPadding();
                    } else {
                        throw log.incompleteDecode();
                    }
                }
                int b1 = NumericIterator.this.next();
                if (b1 == '=') {
                    throw log.unexpectedPadding();
                }
                o0 = calc0(b0, b1);
                if (! NumericIterator.this.hasNext()) {
                    if (requirePadding) {
                        throw log.expectedPadding();
                    }
                    state = 0x19;
                    return true;
                }
                int b2 = NumericIterator.this.next();
                if (b2 == '=') {
                    for (int i = 0; i < 5; i++) {
                        if (! NumericIterator.this.hasNext()) {
                            throw log.expectedPaddingCharacters(6);
                        }
                        if (NumericIterator.this.next() != '=') {
                            throw log.expectedPaddingCharacters(6);
                        }
                    }
                    state = 0x0f;
                    return true;
                }
                if (! NumericIterator.this.hasNext()) {
                    if (requirePadding) {
                        throw log.expectedPadding();
                    } else {
                        throw log.incompleteDecode();
                    }
                }
                int b3 = NumericIterator.this.next();
                if (b3 == '=') {
                    throw log.unexpectedPadding();
                }
                o1 = calc1(b1, b2, b3);
                if (! NumericIterator.this.hasNext()) {
                    if (requirePadding) {
                        throw log.expectedPadding();
                    }
                    state = 0x17;
                    return true;
                }
                int b4 = NumericIterator.this.next();
                if (b4 == '=') {
                    for (int i = 0; i < 3; i++) {
                        if (! NumericIterator.this.hasNext()) {
                            throw log.expectedPaddingCharacters(4);
                        }
                        if (NumericIterator.this.next() != '=') {
                            throw log.expectedPaddingCharacters(4);
                        }
                    }
                    state = 0x0d;
                    return true;
                }
                o2 = calc2(b3, b4);
                if (! NumericIterator.this.hasNext()) {
                    if (requirePadding) {
                        throw log.expectedPadding();
                    }
                    state = 0x14;
                    return true;
                }
                int b5 = NumericIterator.this.next();
                if (b5 == '=') {
                    for (int i = 0; i < 2; i++) {
                        if (! NumericIterator.this.hasNext()) {
                            throw log.expectedPaddingCharacters(3);
                        }
                        if (NumericIterator.this.next() != '=') {
                            throw log.expectedPaddingCharacters(3);
                        }
                    }
                    state = 0x0a;
                    return true;
                }
                if (! NumericIterator.this.hasNext()) {
                    if (requirePadding) {
                        throw log.expectedPadding();
                    } else {
                        throw log.incompleteDecode();
                    }
                }
                int b6 = NumericIterator.this.next();
                if (b6 == '=') {
                    throw log.unexpectedPadding();
                }
                o3 = calc3(b4, b5, b6);
                if (! NumericIterator.this.hasNext()) {
                    if (requirePadding) {
                        throw log.expectedPadding();
                    }
                    state = 0x10;
                    return true;
                }
                int b7 = NumericIterator.this.next();
                if (b7 == '=') {
                    state = 0x06;
                    return true;
                }
                o4 = calc4(b6, b7);
                state = 1;
                return true;
            } else {
                return state < 0x1a;
            }
        }

        public boolean hasPrev() {
            return offset > 0;
        }

        abstract int calc0(int b0, int b1);

        abstract int calc1(int b1, int b2, int b3);

        abstract int calc2(int b3, int b4);

        abstract int calc3(int b4, int b5, int b6);

        abstract int calc4(int b6, int b7);

        public int next() {
            if (! hasNext()) {
                throw new NoSuchElementException();
            }
            switch (state) {
                case 1:
                case 6:
                case 0x0a:
                case 0x0d:
                case 0x10:
                case 0x14:
                case 0x17: {
                    state ++;
                    offset ++;
                    return o0;
                }
                case 2:
                case 7:
                case 0x0b:
                case 0x11:
                case 0x15: {
                    state ++;
                    offset ++;
                    return o1;
                }
                case 3:
                case 8:
                case 0x12: {
                    state ++;
                    offset ++;
                    return o2;
                }
                case 4: {
                    state = 5;
                    offset ++;
                    return o3;
                }
                case 5: {
                    state = 0;
                    offset ++;
                    return o4;
                }
                case 9: {
                    state = 0x1a;
                    offset ++;
                    return o3;
                }
                case 0x0c: {
                    state = 0x1b;
                    offset ++;
                    return o2;
                }
                case 0x0e: {
                    state = 0x1c;
                    offset ++;
                    return o1;
                }
                case 0x0f: {
                    state = 0x1d;
                    offset ++;
                    return o0;
                }
                case 0x13: {
                    state = 0x1e;
                    offset ++;
                    return o3;
                }
                case 0x16: {
                    state = 0x1f;
                    offset ++;
                    return o2;
                }
                case 0x18: {
                    state = 0x20;
                    offset ++;
                    return o1;
                }
                case 0x19: {
                    state = 0x21;
                    offset ++;
                    return o0;
                }
                default: {
                    // padding
                    throw new NoSuchElementException();
                }
            }
        }

        public int peekNext() throws NoSuchElementException {
            if (! hasNext()) {
                throw new NoSuchElementException();
            }
            switch (state) {
                case 1:
                case 6:
                case 0x0a:
                case 0x0d:
                case 0x0f:
                case 0x10:
                case 0x14:
                case 0x17:
                case 0x19: {
                    return o0;
                }
                case 2:
                case 7:
                case 0x0b:
                case 0x0e:
                case 0x11:
                case 0x15:
                case 0x18: {
                    return o1;
                }
                case 3:
                case 8:
                case 0x0c:
                case 0x12:
                case 0x16: {
                    return o2;
                }
                case 4:
                case 9:
                case 0x13: {
                    return o3;
                }
                case 5: {
                    return o4;
                }
                default: {
                    // padding
                    throw new NoSuchElementException();
                }
            }
        }

        public int prev() {
            if (! hasPrev()) {
                throw new NoSuchElementException();
            }
            int skipChars = 0;
            switch (state) {
                case 0:
                case 1:
                case 6:
                case 0x0a:
                case 0x0d:
                case 0x0f:
                case 0x10:
                case 0x14:
                case 0x17:
                case 0x19: {
                    if (state == 6 || state == 0x0a || state == 0x0d || state == 0x0f) {
                        skipChars = 8;
                    } else if (state == 0x10) {
                        skipChars = 7;
                    } else if (state == 0x14) {
                        skipChars = 5;
                    } else if (state == 0x17) {
                        skipChars = 4;
                    } else if (state == 0x19) {
                        skipChars = 2;
                    }
                    for (int i = 0; i < skipChars; i++) {
                        NumericIterator.this.prev(); // consume character
                    }
                    int b7 = NumericIterator.this.prev();
                    int b6 = NumericIterator.this.prev();
                    int b5 = NumericIterator.this.prev();
                    int b4 = NumericIterator.this.prev();
                    int b3 = NumericIterator.this.prev();
                    int b2 = NumericIterator.this.prev();
                    int b1 = NumericIterator.this.prev();
                    int b0 = NumericIterator.this.prev();
                    o0 = calc0(b0, b1);
                    o1 = calc1(b1, b2, b3);
                    o2 = calc2(b3, b4);
                    o3 = calc3(b4, b5, b6);
                    o4 = calc4(b6, b7);
                    state = 5;
                    offset --;
                    return o4;
                }
                case 2:
                case 7:
                case 0x0b:
                case 0x0e:
                case 0x11:
                case 0x15:
                case 0x18: {
                    state --;
                    offset --;
                    return o0;
                }
                case 3:
                case 8:
                case 0x0c:
                case 0x12:
                case 0x16: {
                    state --;
                    offset --;
                    return o1;
                }
                case 4:
                case 9:
                case 0x13: {
                    state --;
                    offset --;
                    return o2;
                }
                case 5: {
                    state = 4;
                    offset --;
                    return o3;
                }
                case 0x1a: {
                    state = 9;
                    offset --;
                    return o3;
                }
                case 0x1b: {
                    state = 0x0c;
                    offset --;
                    return o2;
                }
                case 0x1c: {
                    state = 0x0e;
                    offset --;
                    return o1;
                }
                case 0x1d: {
                    state = 0x0f;
                    offset --;
                    return o0;
                }
                case 0x1e: {
                    state = 0x13;
                    offset --;
                    return o3;
                }
                case 0x1f: {
                    state = 0x16;
                    offset --;
                    return o2;
                }
                case 0x20: {
                    state = 0x18;
                    offset --;
                    return o1;
                }
                case 0x21: {
                    state = 0x19;
                    offset --;
                    return o0;
                }
                default: {
                    throw new NoSuchElementException();
                }
            }
        }

        public int peekPrev() throws NoSuchElementException {
            if (! hasPrev()) {
                throw new NoSuchElementException();
            }
            int skipChars = 0;
            switch (state) {
                case 0:
                case 1:
                case 6:
                case 0x0a:
                case 0x0d:
                case 0x0f:
                case 0x10:
                case 0x14:
                case 0x17:
                case 0x19: {
                    if (state == 6 || state == 0x0a || state == 0x0d || state == 0x0f) {
                        skipChars = 8;
                    } else if (state == 0x10) {
                        skipChars = 7;
                    } else if (state == 0x14) {
                        skipChars = 5;
                    } else if (state == 0x17) {
                        skipChars = 4;
                    } else if (state == 0x19) {
                        skipChars = 2;
                    }
                    for (int i = 0; i < skipChars; i++) {
                        NumericIterator.this.prev(); // consume character
                    }
                    int b7 = NumericIterator.this.prev();
                    int b6 = NumericIterator.this.peekPrev();
                    NumericIterator.this.next();
                    for (int i = 0; i < skipChars; i++) {
                        NumericIterator.this.next();
                    }
                    return calc4(b6, b7);
                }
                case 2:
                case 7:
                case 0x0b:
                case 0x0e:
                case 0x11:
                case 0x15:
                case 0x18:
                case 0x1d:
                case 0x21: {
                    return o0;
                }
                case 3:
                case 8:
                case 0x0c:
                case 0x12:
                case 0x16:
                case 0x1c:
                case 0x20: {
                    return o1;
                }
                case 4:
                case 9:
                case 0x13:
                case 0x1b:
                case 0x1f: {
                    return o2;
                }
                case 5:
                case 0x1a:
                case 0x1e: {
                    return o3;
                }
                default: {
                    throw new NoSuchElementException();
                }
            }
        }

        public int offset() {
            return offset;
        }
    }

    public ByteIterator base64Decode(final Base64Alphabet alphabet, boolean requirePadding) {
        if (! hasNext()) return ByteIterator.EMPTY;
        if (alphabet.littleEndian) {
            return this.new Base64ByteIterator(requirePadding) {
                int calc0(final int b0, final int b1) {
                    final int d0 = alphabet.decode(b0);
                    final int d1 = alphabet.decode(b1);
                    // d0 = r0[5..0]
                    // d1 = r1[3..0] + r0[7..6]
                    if (d0 == -1 || d1 == -1) throw log.invalidBase64Character();
                    return (d0 | d1 << 6) & 0xff;
                }

                int calc1(final int b1, final int b2) {
                    final int d1 = alphabet.decode(b1);
                    final int d2 = alphabet.decode(b2);
                    // d1 = r1[3..0] + r0[7..6]
                    // d2 = r2[1..0] + r1[7..4]
                    if (d1 == -1 || d2 == -1) throw log.invalidBase64Character();
                    return (d1 >> 2 | d2 << 4) & 0xff;
                }

                int calc2(final int b2, final int b3) {
                    final int d2 = alphabet.decode(b2);
                    final int d3 = alphabet.decode(b3);
                    // d2 = r2[1..0] + r1[7..4]
                    // d3 = r2[7..2]
                    if (d2 == -1 || d3 == -1) throw log.invalidBase64Character();
                    return (d2 >> 4 | d3 << 2) & 0xff;
                }
            };
        } else {
            return this.new Base64ByteIterator(requirePadding) {
                int calc0(final int b0, final int b1) {
                    final int d0 = alphabet.decode(b0);
                    final int d1 = alphabet.decode(b1);
                    // d0 = r0[7..2]
                    // d1 = r0[1..0] + r1[7..4]
                    if (d0 == -1 || d1 == -1) throw log.invalidBase64Character();
                    return (d0 << 2 | d1 >> 4) & 0xff;
                }

                int calc1(final int b1, final int b2) {
                    final int d1 = alphabet.decode(b1);
                    final int d2 = alphabet.decode(b2);
                    // d1 = r0[1..0] + r1[7..4]
                    // d2 = r1[3..0] + r2[7..6]
                    if (d1 == -1 || d2 == -1) throw log.invalidBase64Character();
                    return (d1 << 4 | d2 >> 2) & 0xff;
                }

                int calc2(final int b2, final int b3) {
                    final int d2 = alphabet.decode(b2);
                    final int d3 = alphabet.decode(b3);
                    // d2 = r1[3..0] + r2[7..6]
                    // d3 = r2[5..0]
                    if (d2 == -1 || d3 == -1) throw log.invalidBase64Character();
                    return (d2 << 6 | d3) & 0xff;
                }
            };
        }
    }

    public ByteIterator base32Decode(final Base32Alphabet alphabet, boolean requirePadding) {
        if (! hasNext()) return ByteIterator.EMPTY;
        if (alphabet.littleEndian) {
            return this.new Base32ByteIterator(requirePadding) {
                int calc0(final int b0, final int b1) {
                    final int d0 = alphabet.decode(b0);
                    final int d1 = alphabet.decode(b1);
                    // d0 = r0[4..0]
                    // d1 = r1[1..0] + r0[7..5]
                    if (d0 == -1 || d1 == -1) throw log.invalidBase32Character();
                    return (d0 | d1 << 5) & 0xff;
                }

                int calc1(final int b1, final int b2, final int b3) {
                    final int d1 = alphabet.decode(b1);
                    final int d2 = alphabet.decode(b2);
                    final int d3 = alphabet.decode(b3);
                    // d1 = r1[1..0] + r0[7..5]
                    // d2 = r1[6..2]
                    // d3 = r2[3..0] + r1[7]
                    if (d1 == -1 || d2 == -1 || d3 == -1) throw log.invalidBase32Character();
                    return (d1 >> 3 | d2 << 2 | d3 << 7) & 0xff;
                }

                int calc2(final int b3, final int b4) {
                    final int d3 = alphabet.decode(b3);
                    final int d4 = alphabet.decode(b4);
                    // d3 = r2[3..0] + r1[7]
                    // d4 = r3[0] + r2[7..4]
                    if (d3 == -1 || d4 == -1) throw log.invalidBase32Character();
                    return (d3 >> 1 | d4 << 4) & 0xff;
                }

                int calc3(final int b4, final int b5, final int b6) {
                    final int d4 = alphabet.decode(b4);
                    final int d5 = alphabet.decode(b5);
                    final int d6 = alphabet.decode(b6);
                    // d4 = r3[0] + r2[7..4]
                    // d5 = r3[5..1]
                    // d6 = r4[2..0] + r3[7..6]
                    if (d4 == -1 || d5 == -1 || d6 == -1) throw log.invalidBase32Character();
                    return (d4 >> 4 | d5 << 1 | d6 << 6) & 0xff;
                }

                int calc4(final int b6, final int b7) {
                    final int d6 = alphabet.decode(b6);
                    final int d7 = alphabet.decode(b7);
                    // d6 = r4[2..0] + r3[7..6]
                    // d7 = r4[7..3]
                    if (d6 == -1 || d7 == -1) throw log.invalidBase32Character();
                    return (d6 >> 2 | d7 << 3) & 0xff;
                }
            };
        } else {
            return this.new Base32ByteIterator(requirePadding) {
                int calc0(final int b0, final int b1) {
                    final int d0 = alphabet.decode(b0);
                    final int d1 = alphabet.decode(b1);
                    // d0 = r0[7..3]
                    // d1 = r0[2..0] + r1[7..6]
                    if (d0 == -1 || d1 == -1) throw log.invalidBase32Character();
                    return (d0 << 3 | d1 >> 2) & 0xff;
                }

                int calc1(final int b1, final int b2, final int b3) {
                    final int d1 = alphabet.decode(b1);
                    final int d2 = alphabet.decode(b2);
                    final int d3 = alphabet.decode(b3);
                    // d1 = r0[2..0] + r1[7..6]
                    // d2 = r1[5..1]
                    // d3 = r1[0] + r2[7..4]
                    if (d1 == -1 || d2 == -1 || d3 == -1) throw log.invalidBase32Character();
                    return (d1 << 6 | d2 << 1 | d3 >> 4) & 0xff;
                }

                int calc2(final int b3, final int b4) {
                    final int d3 = alphabet.decode(b3);
                    final int d4 = alphabet.decode(b4);
                    // d3 = r1[0] + r2[7..4]
                    // d4 = r2[3..0] + r3[7]
                    if (d3 == -1 || d4 == -1) throw log.invalidBase32Character();
                    return (d3 << 4 | d4 >> 1) & 0xff;
                }

                int calc3(final int b4, final int b5, final int b6) {
                    final int d4 = alphabet.decode(b4);
                    final int d5 = alphabet.decode(b5);
                    final int d6 = alphabet.decode(b6);
                    // d4 = r2[3..0] + r3[7]
                    // d5 = r3[6..2]
                    // d6 = r3[1..0] + r4[7..5]
                    if (d4 == -1 || d5 == -1 || d6 == -1) throw log.invalidBase32Character();
                    return (d4 << 7 | d5 << 2  | d6 >> 3) & 0xff;
                }

                int calc4(final int b6, final int b7) {
                    final int d6 = alphabet.decode(b6);
                    final int d7 = alphabet.decode(b7);
                    // d6 = r3[1..0] + r4[7..5]
                    // d7 = r4[4..0]
                    if (d6 == -1 || d7 == -1) throw log.invalidBase32Character();
                    return (d6 << 5 | d7) & 0xff;
                }
            };
        }
    }

    public ByteIterator hexDecode() {
        if (! hasNext()) return ByteIterator.EMPTY;
        return new ByteIterator() {
            private int b;
            private int offset;
            private boolean havePair;

            private int calc(final int b0, final int b1) {
                int d0 = Character.digit(b0, 16);
                int d1 = Character.digit(b1, 16);
                if (d0 == -1 || d1 == -1) throw log.invalidHexCharacter();
                return ((d0 << 4) | d1) & 0xff;
            }

            public boolean hasNext() {
                if (havePair) {
                    return true;
                }
                if (! NumericIterator.this.hasNext()) {
                    return false;
                }
                int b0 = NumericIterator.this.next();
                if (! NumericIterator.this.hasNext()) {
                    throw log.expectedEvenNumberOfHexCharacters();
                }
                int b1 = NumericIterator.this.next();
                b = calc(b0, b1);
                havePair = true;
                return true;
            }

            public boolean hasPrev() {
                return offset > 0;
            }

            public int next() throws NoSuchElementException {
                if (! hasNext()) {
                    throw new NoSuchElementException();
                }
                offset ++;
                havePair = false;
                return b;
            }

            public int peekNext() throws NoSuchElementException {
                if (! hasNext()) {
                    throw new NoSuchElementException();
                }
                return b;
            }

            public int prev() throws NoSuchElementException {
                if (! hasPrev()) {
                    throw new NoSuchElementException();
                }
                int b1 = NumericIterator.this.prev();
                int b0 = NumericIterator.this.prev();
                b = calc(b0, b1);
                offset --;
                havePair = true;
                return b;
            }

            public int peekPrev() throws NoSuchElementException {
                if (! hasPrev()) {
                    throw new NoSuchElementException();
                }
                int b1 = NumericIterator.this.prev();
                int b0 = NumericIterator.this.peekPrev();
                NumericIterator.this.next();
                return calc(b0, b1);
            }

            public int offset() {
                return offset;
            }
        };
    }
}
