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

package org.wildfly.security.asn1;

import static org.wildfly.security.asn1.ASN1.*;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.NoSuchElementException;

import org.wildfly.security.util.ByteIterator;

/**
 * A class used to decode ASN.1 values that have been encoded using the Distinguished Encoding Rules (DER).
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public class DERDecoder implements ASN1Decoder {

    private ByteIterator bi;
    private ArrayDeque<DecoderState> states = new ArrayDeque<DecoderState>();
    private int implicitTag = -1;

    /**
     * Create a DER decoder that will decode values from the given byte array.
     *
     * @param buf the byte array to decode
     */
    public DERDecoder(byte[] buf) {
        this.bi = ByteIterator.ofBytes(buf);
    }

    /**
     * Create a DER decoder that will decode values from the given byte array.
     *
     * @param buf the byte array to decode
     * @param offset the offset in the byte array of the first byte to read
     * @param the maximum number of bytes to read from the byte array
     */
    public DERDecoder(byte[] buf, int offset, int length) {
        this.bi = ByteIterator.ofBytes(buf, offset, length);
    }

    /**
     * Create a DER decoder that will decode values from the given {@code ByteIterator}.
     *
     * @param src the {@code ByteIterator} from which DER encoded values will be decoded
     */
    public DERDecoder(ByteIterator bi) {
        this.bi = bi;
    }

    @Override
    public void startSequence() throws ASN1Exception {
        readTag(SEQUENCE_TYPE);
        int length = readLength();
        states.add(new DecoderState(SEQUENCE_TYPE, bi.offset() + length));
    }

    @Override
    public void endSequence() throws ASN1Exception {
        DecoderState lastState = states.peekLast();
        if ((lastState == null) || (lastState.getTag() != SEQUENCE_TYPE)) {
            throw new IllegalStateException("No sequence to end");
        }
        endConstructedElement(lastState.getNextElementIndex());
        states.removeLast();
    }

    @Override
    public void startSet() throws ASN1Exception {
        readTag(SET_TYPE);
        int length = readLength();
        states.add(new DecoderState(SET_TYPE, bi.offset() + length));
    }

    @Override
    public void endSet() throws ASN1Exception {
        DecoderState lastState = states.peekLast();
        if ((lastState == null) || (lastState.getTag() != SET_TYPE)) {
            throw new IllegalStateException("No set to end");
        }
        endConstructedElement(lastState.getNextElementIndex());
        states.removeLast();
    }

    @Override
    public void startSetOf() throws ASN1Exception {
        startSet();
    }

    @Override
    public void endSetOf() throws ASN1Exception {
        endSet();
    }

    private void endConstructedElement(int nextElementIndex) throws ASN1Exception {
        int pos = bi.offset();
        if (pos < nextElementIndex) {
            // Any elements in this constructed element that have not yet been read will be discarded
            int i;
            for (i = 0; i < (nextElementIndex - pos) && bi.hasNext(); i++) {
                bi.next();
            }
            if (i != (nextElementIndex - pos)) {
                throw new ASN1Exception("Unexpected end of input");
            }
        } else if (pos > nextElementIndex) {
            // Shouldn't happen
            throw new IllegalStateException();
        }
    }

    @Override
    public byte[] decodeOctetString() throws ASN1Exception {
        readTag(OCTET_STRING_TYPE);
        int length = readLength();
        byte[] result = new byte[length];
        if ((length != 0) && (bi.drain(result, 0, length) != length)) {
            throw new ASN1Exception("Unexpected end of input");
        }
        return result;
    }

    @Override
    public String decodeOctetStringAsString() throws ASN1Exception {
        return decodeOctetStringAsString(StandardCharsets.UTF_8.name());
    }

    @Override
    public String decodeOctetStringAsString(String charSet) throws ASN1Exception {
        readTag(OCTET_STRING_TYPE);
        int length = readLength();
        byte[] octets = new byte[length];
        if ((length != 0) && (bi.drain(octets, 0, length) != length)) {
            throw new ASN1Exception("Unexpected end of input");
        }
        try {
            return new String(octets, charSet);
        } catch (UnsupportedEncodingException e) {
            throw new ASN1Exception(e.getMessage());
        }
    }

    @Override
    public String decodeIA5String() throws ASN1Exception {
        byte[] octets = decodeIA5StringAsBytes();
        return new String(octets, StandardCharsets.US_ASCII);
    }

    @Override
    public byte[] decodeIA5StringAsBytes() throws ASN1Exception {
        readTag(IA5_STRING_TYPE);
        int length = readLength();
        byte[] result = new byte[length];
        if ((length != 0) && (bi.drain(result, 0, length) != length)) {
            throw new ASN1Exception("Unexpected end of input");
        }
        return result;
    }

    @Override
    public byte[] decodeBitString() throws ASN1Exception {
        readTag(BIT_STRING_TYPE);
        int length = readLength();
        byte[] result = new byte[length - 1];

        int numUnusedBits = bi.next();
        if (numUnusedBits < 0 || numUnusedBits > 7) {
            throw new ASN1Exception("Invalid number of unused bits");
        }

        if (numUnusedBits == 0) {
            for (int i = 0; i < (length -1); i++) {
                result[i] = (byte) bi.next();
            }
        } else {
            // Any unused bits will be removed
            int leftShift = 8 - numUnusedBits;
            int previous = 0;
            int next;
            for (int i = 0; i < (length -1); i++) {
                next = bi.next();
                if (i == 0) {
                    result[i] = (byte) (next >>> numUnusedBits);
                } else {
                    result[i] = (byte) ((next >>> numUnusedBits) | (previous << leftShift));
                }
                previous = next;
            }
        }
        return result;
    }

    @Override
    public String decodeBitStringAsString() throws ASN1Exception {
        readTag(BIT_STRING_TYPE);
        int length = readLength();
        int numUnusedBits = bi.next();
        if (numUnusedBits < 0 || numUnusedBits > 7) {
            throw new ASN1Exception("Invalid number of unused bits");
        }

        int k = 0, next;
        int numBits = (length - 1) * 8 - numUnusedBits;
        StringBuilder result = new StringBuilder(numBits);
        for (int i = 0; i < (length - 1); i++) {
            next = bi.next();
            for (int j = 7; j >= 0 && k < numBits; j--) {
                if ((next & (1 << j)) != 0) {
                    result.append("1");
                } else {
                    result.append("0");
                }
                k += 1;
            }
        }
        return result.toString();
    }

    @Override
    public String decodeObjectIdentifier() throws ASN1Exception {
        readTag(OBJECT_IDENTIFIER_TYPE);
        int length = readLength();
        int octet;
        long value = 0;
        BigInteger bigInt = null;
        boolean processedFirst = false;
        StringBuffer objectIdentifierStr = new StringBuffer();

        for (int i = 0; i < length; i++) {
            octet = bi.next();
            if (value < 0x80000000000000L) {
                value = (value << 7) + (octet & 0x7f);
                if ((octet & 0x80) == 0) {
                    // Reached the end of a component value
                    if (!processedFirst) {
                        int first = ((int) value / 40);
                        if (first == 0) {
                            objectIdentifierStr.append("0");
                        } else if (first == 1) {
                            value = value - 40;
                            objectIdentifierStr.append("1");
                        } else if (first == 2) {
                            value = value - 80;
                            objectIdentifierStr.append("2");
                        }
                        processedFirst = true;
                    }
                    objectIdentifierStr.append('.');
                    objectIdentifierStr.append(value);

                    // Reset for the next component value
                    value = 0;
                }
            } else {
                if (bigInt == null) {
                    bigInt = BigInteger.valueOf(value);
                }
                bigInt = bigInt.shiftLeft(7).add(BigInteger.valueOf(octet & 0x7f));
                if ((octet & 0x80) == 0) {
                    // Reached the end of a component value
                    objectIdentifierStr.append('.');
                    objectIdentifierStr.append(bigInt);

                    // Reset for the next component value
                    bigInt = null;
                    value = 0;
                }
            }
        }
        return objectIdentifierStr.toString();
    }

    @Override
    public void decodeNull() throws ASN1Exception {
        readTag(NULL_TYPE);
        int length = readLength();
        if (length != 0) {
            throw new ASN1Exception("Non-zero length encountered for null type tag");
        }
    }

    @Override
    public void decodeImplicit(int number) {
        decodeImplicit(CONTEXT_SPECIFIC_MASK, number);
    }

    @Override
    public void decodeImplicit(int clazz, int number) {
        if (implicitTag == -1) {
            implicitTag = clazz | number;
        }
    }

    @Override
    public boolean isNextType(int clazz, int number, boolean isConstructed) throws ASN1Exception {
        return peekType() == (clazz | (isConstructed ? CONSTRUCTED_MASK : 0x00) | number);
    }

    @Override
    public int peekType() throws ASN1Exception {
        int currOffset = bi.offset();
        int tag = readTag();
        while ((bi.offset() != currOffset) && bi.hasPrev()) {
            bi.prev();
        }
        return tag;
    }

    @Override
    public void skipElement() throws ASN1Exception {
        readTag();
        int length = readLength();
        int i;
        for (i = 0; i < length && bi.hasNext(); i++) {
            bi.next();
        }
        if (i != length) {
            throw new ASN1Exception("Unexpected end of input");
        }
    }

    @Override
    public boolean hasNextElement() {
        boolean hasNext = false;
        int currOffset = bi.offset();
        try {
            int tag = readTag();
            int length = readLength();
            int i;
            for (i = 0; (i < length) && bi.hasNext(); i++) {
                bi.next();
            }
            hasNext = (i == length);
        } catch (ASN1Exception e) {
            hasNext = false;
        }
        while ((bi.offset() != currOffset) && bi.hasPrev()) {
            bi.prev();
        }
        return hasNext;
    }

    private int readTag() throws ASN1Exception {
        try {
            int tag = bi.next();
            int tagClass = tag & CLASS_MASK;
            int constructed = tag & CONSTRUCTED_MASK;
            int tagNumber = tag & TAG_NUMBER_MASK;
            if (tagNumber == 0x1f) {
                // High-tag-number form
                tagNumber = 0;
                int octet = bi.next();
                if ((octet & 0x7f) == 0) {
                    // Bits 7 to 1 of the first subsequent octet cannot be 0
                    throw new ASN1Exception("Invalid high-tag-number form");
                }
                while ((octet >= 0) && ((octet & 0x80) != 0)) {
                    tagNumber |= (octet & 0x7f);
                    tagNumber <<= 7;
                    octet = bi.next();
                }
                tagNumber |= (octet & 0x7f);
            }
            return (tagClass | constructed | tagNumber);
        } catch (NoSuchElementException e) {
            throw new ASN1Exception("Unexpected end of input");
        }
    }

    private void readTag(int expectedTag) throws ASN1Exception {
        if (implicitTag != -1) {
            expectedTag = implicitTag | (expectedTag & CONSTRUCTED_MASK);
            implicitTag = -1;
        }
        int currOffset = bi.offset();
        int actualTag = readTag();
        if (actualTag != expectedTag) {
            while ((bi.offset() != currOffset) && bi.hasPrev()) {
                bi.prev();
            }
            throw new ASN1Exception("Unexpected ASN.1 tag encountered");
        }
    }

    private int readLength() throws ASN1Exception {
        try {
            int length = bi.next();
            if (length > 127) {
                // Long form
                int numOctets = length & 0x7f;
                if (numOctets > 4) {
                    throw new ASN1Exception("Length encoding exceeds 4 bytes");
                }
                length = 0;
                int nextOctet;
                for (int i = 0; i < numOctets; i++) {
                    nextOctet = bi.next();
                    length = (length << 8) + nextOctet;
                }
            }
            return length;
        } catch (NoSuchElementException e) {
            throw new ASN1Exception("Unexpected end of input");
        }
    }

    /**
     * A class used to maintain state information during DER decoding.
     */
    private class DecoderState {
        // Tag number for a constructed element
        private final int tag;

        // The position of the first character in the encoded buffer that occurs after
        // the encoding of the constructed element
        private final int nextElementIndex;

        public DecoderState(int tag, int nextElementIndex) {
            this.tag = tag;
            this.nextElementIndex = nextElementIndex;
        }

        public int getTag() {
            return tag;
        }

        public int getNextElementIndex() {
            return nextElementIndex;
        }
    }
}
