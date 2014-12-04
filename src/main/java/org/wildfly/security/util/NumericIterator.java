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
 * Non-public numeric iterator base class.  It is important to keep this non-public to prevent type confusion between
 * byte and code point iterators, which are fundamentally incompatible.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
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
                    throw new DecodeException("Unexpected padding");
                }
                if (! NumericIterator.this.hasNext()) {
                    if (requirePadding) {
                        throw new DecodeException("Expected padding");
                    } else {
                        throw new DecodeException("Incomplete decode");
                    }
                }
                int b1 = NumericIterator.this.next();
                if (b1 == '=') {
                    throw new DecodeException("Unexpected padding");
                }
                o0 = calc0(b0, b1);
                if (! NumericIterator.this.hasNext()) {
                    if (requirePadding) {
                        throw new DecodeException("Expected padding");
                    }
                    state = 9;
                    return true;
                }
                int b2 = NumericIterator.this.next();
                if (b2 == '=') {
                    if (! NumericIterator.this.hasNext()) {
                        throw new DecodeException("Expected two padding characters");
                    }
                    if (NumericIterator.this.next() != '=') {
                        throw new DecodeException("Expected two padding characters");
                    }
                    state = 6;
                    return true;
                }
                o1 = calc1(b1, b2);
                if (! NumericIterator.this.hasNext()) {
                    if (requirePadding) {
                        throw new DecodeException("Expected padding");
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

    public ByteIterator base64Decode(final Alphabet alphabet, boolean requirePadding) {
        if (! hasNext()) return ByteIterator.EMPTY;
        if (alphabet.littleEndian) {
            return new Base64ByteIterator(requirePadding) {
                int calc0(final int b0, final int b1) {
                    final int d0 = alphabet.decode(b0);
                    final int d1 = alphabet.decode(b1);
                    // d0 = r0[5..0]
                    // d1 = r1[3..0] + r0[7..6]
                    if (d0 == -1 || d1 == -1) throw new DecodeException("Invalid base 64 character");
                    return (d0 | d1 << 6) & 0xff;
                }

                int calc1(final int b1, final int b2) {
                    final int d1 = alphabet.decode(b1);
                    final int d2 = alphabet.decode(b2);
                    // d1 = r1[3..0] + r0[7..6]
                    // d2 = r2[1..0] + r1[7..4]
                    if (d1 == -1 || d2 == -1) throw new DecodeException("Invalid base 64 character");
                    return (d1 >> 2 | d2 << 4) & 0xff;
                }

                int calc2(final int b2, final int b3) {
                    final int d2 = alphabet.decode(b2);
                    final int d3 = alphabet.decode(b3);
                    // d2 = r2[1..0] + r1[7..4]
                    // d3 = r2[7..2]
                    if (d2 == -1 || d3 == -1) throw new DecodeException("Invalid base 64 character");
                    return (d2 << 2 | d3 >> 4) & 0xff;
                }
            };
        } else {
            return new Base64ByteIterator(requirePadding) {
                int calc0(final int b0, final int b1) {
                    final int d0 = alphabet.decode(b0);
                    final int d1 = alphabet.decode(b1);
                    // d0 = r0[7..2]
                    // d1 = r0[1..0] + r1[7..4]
                    if (d0 == -1 || d1 == -1) throw new DecodeException("Invalid base 64 character");
                    return (d0 << 2 | d1 >> 4) & 0xff;
                }

                int calc1(final int b1, final int b2) {
                    final int d1 = alphabet.decode(b1);
                    final int d2 = alphabet.decode(b2);
                    // d1 = r0[1..0] + r1[7..4]
                    // d2 = r1[3..0] + r2[7..6]
                    if (d1 == -1 || d2 == -1) throw new DecodeException("Invalid base 64 character");
                    return (d1 << 4 | d2 >> 2) & 0xff;
                }

                int calc2(final int b2, final int b3) {
                    final int d2 = alphabet.decode(b2);
                    final int d3 = alphabet.decode(b3);
                    // d2 = r1[3..0] + r2[7..6]
                    // d3 = r2[5..0]
                    if (d2 == -1 || d3 == -1) throw new DecodeException("Invalid base 64 character");
                    return (d2 << 6 | d3) & 0xff;
                }
            };
        }
    }
}
