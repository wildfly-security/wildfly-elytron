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

import static org.wildfly.security.asn1.ElytronMessages.log;
import static org.wildfly.security.asn1.ASN1.*;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.NoSuchElementException;

import org.wildfly.common.iteration.ByteIterator;

/**
 * A class used to decode ASN.1 values that have been encoded using the Distinguished Encoding Rules (DER).
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public class DERDecoder implements ASN1Decoder {

    private static final int BOOLEAN_FALSE = 0;

    private static final Charset UTF_32BE = Charset.forName("UTF-32BE");

    private final ByteIterator bi;
    private final ArrayDeque<DecoderState> states = new ArrayDeque<DecoderState>();
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
     * @param length the maximum number of bytes to read from the byte array
     */
    public DERDecoder(byte[] buf, int offset, int length) {
        this.bi = ByteIterator.ofBytes(buf, offset, length);
    }

    /**
     * Create a DER decoder that will decode values from the given {@code ByteIterator}.
     *
     * @param bi the {@code ByteIterator} from which DER encoded values will be decoded
     */
    DERDecoder(ByteIterator bi) {
        this.bi = bi;
    }

    @Override
    public void startSequence() throws ASN1Exception {
        readTag(SEQUENCE_TYPE);
        int length = readLength();
        states.add(new DecoderState(SEQUENCE_TYPE, bi.getIndex() + length));
    }

    @Override
    public void endSequence() throws ASN1Exception {
        DecoderState lastState = states.peekLast();
        if ((lastState == null) || (lastState.getTag() != SEQUENCE_TYPE)) {
            throw log.noSequenceToEnd();
        }
        endConstructedElement(lastState.getNextElementIndex());
        states.removeLast();
    }

    @Override
    public void startSet() throws ASN1Exception {
        readTag(SET_TYPE);
        int length = readLength();
        states.add(new DecoderState(SET_TYPE, bi.getIndex() + length));
    }

    @Override
    public void endSet() throws ASN1Exception {
        DecoderState lastState = states.peekLast();
        if ((lastState == null) || (lastState.getTag() != SET_TYPE)) {
            throw log.noSetToEnd();
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

    @Override
    public void startExplicit(int number) throws ASN1Exception {
        startExplicit(CONTEXT_SPECIFIC_MASK, number);
    }

    @Override
    public void startExplicit(int clazz, int number) throws ASN1Exception {
        int explicitTag = clazz | CONSTRUCTED_MASK | number;
        readTag(explicitTag);
        int length = readLength();
        states.add(new DecoderState(explicitTag, bi.getIndex() + length));
    }

    @Override
    public void endExplicit() throws ASN1Exception {
        DecoderState lastState = states.peekLast();
        if ((lastState == null) || (lastState.getTag() == SEQUENCE_TYPE)
                || (lastState.getTag() == SET_TYPE) || ((lastState.getTag() & CONSTRUCTED_MASK) == 0)) {
            throw log.noExplicitlyTaggedElementToEnd();
        }
        endConstructedElement(lastState.getNextElementIndex());
        states.removeLast();
    }

    private void endConstructedElement(long nextElementIndex) throws ASN1Exception {
        long pos = bi.getIndex();
        if (pos < nextElementIndex) {
            // Any elements in this constructed element that have not yet been read will be discarded
            int i;
            for (i = 0; i < (nextElementIndex - pos) && bi.hasNext(); i++) {
                bi.next();
            }
            if (i != (nextElementIndex - pos)) {
                throw log.asnUnexpectedEndOfInput();
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
            throw log.asnUnexpectedEndOfInput();
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
            throw log.asnUnexpectedEndOfInput();
        }
        try {
            return new String(octets, charSet);
        } catch (UnsupportedEncodingException e) {
            throw new ASN1Exception(e);
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
        return decodeUncheckedStringAsBytes();
    }

    @Override
    public byte[] decodeBitString() throws ASN1Exception {
        readTag(BIT_STRING_TYPE);
        int length = readLength();
        byte[] result = new byte[length - 1];

        int numUnusedBits = bi.next();
        if (numUnusedBits < 0 || numUnusedBits > 7) {
            throw log.asnInvalidNumberOfUnusedBits();
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
    public BigInteger decodeBitStringAsInteger() {
        DERDecoder decoder = new DERDecoder(decodeBitString());

        if (decoder.peekType() != INTEGER_TYPE) {
            throw log.asnUnexpectedTag();
        }

        return decoder.decodeInteger();
    }

    @Override
    public String decodeBitStringAsString() throws ASN1Exception {
        readTag(BIT_STRING_TYPE);
        int length = readLength();
        int numUnusedBits = bi.next();
        if (numUnusedBits < 0 || numUnusedBits > 7) {
            throw log.asnInvalidNumberOfUnusedBits();
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
    public String decodePrintableString() throws ASN1Exception {
        return new String(decodePrintableStringAsBytes(), StandardCharsets.US_ASCII);
    }

    @Override
    public byte[] decodePrintableStringAsBytes() throws ASN1Exception {
        readTag(PRINTABLE_STRING_TYPE);
        final int length = readLength();
        int c = 0;
        byte[] result = new byte[length];
        while (bi.hasNext() && c < length) {
            final int b = bi.next();
            validatePrintableByte(b);
            result[c++] = (byte) b;
        }
        if (c < length) {
            throw log.asnUnexpectedEndOfInput();
        }
        return result;
    }

    @Override
    public String decodeUniversalString() throws ASN1Exception {
        return new String(decodeUniversalStringAsBytes(), UTF_32BE);
    }

    @Override
    public byte[] decodeUniversalStringAsBytes() throws ASN1Exception {
        readTag(UNIVERSAL_STRING_TYPE);
        return decodeUncheckedStringAsBytes();
    }

    @Override
    public String decodeUtf8String() throws ASN1Exception {
        return new String(decodeUtf8StringAsBytes(), StandardCharsets.UTF_8);
    }

    @Override
    public byte[] decodeUtf8StringAsBytes() throws ASN1Exception {
        readTag(UTF8_STRING_TYPE);
        return decodeUncheckedStringAsBytes();
    }

    @Override
    public String decodeBMPString() throws ASN1Exception {
        return new String(decodeBMPStringAsBytes(), StandardCharsets.UTF_16BE);
    }

    @Override
    public byte[] decodeBMPStringAsBytes() throws ASN1Exception {
        readTag(BMP_STRING_TYPE);
        return decodeUncheckedStringAsBytes();
    }

    private byte[] decodeUncheckedStringAsBytes() throws ASN1Exception {
        int length = readLength();
        byte[] result = new byte[length];
        if ((length != 0) && (bi.drain(result, 0, length) != length)) {
            throw log.asnUnexpectedEndOfInput();
        }
        return result;
    }

    @Override
    public String decodeObjectIdentifier() throws ASN1Exception {
        readTag(OBJECT_IDENTIFIER_TYPE);
        int length = readLength();
        int octet;
        long value = 0;
        BigInteger bigInt = null;
        boolean processedFirst = false;
        StringBuilder objectIdentifierStr = new StringBuilder();

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
    public BigInteger decodeInteger() throws ASN1Exception {
        if (INTEGER_TYPE != peekType()) {
            throw log.asnUnexpectedTag();
        }

        return new BigInteger(drainElementValue());
    }

    @Override
    public void decodeNull() throws ASN1Exception {
        readTag(NULL_TYPE);
        int length = readLength();
        if (length != 0) {
            throw log.asnNonZeroLengthForNullTypeTag();
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
    public boolean decodeBoolean() throws ASN1Exception {
        readTag(BOOLEAN_TYPE);
        int length = readLength();
        if (length != 1) {
            throw log.asnInvalidLengthForBooleanTypeTag();
        }
        if (! bi.hasNext()) {
            throw log.asnUnexpectedEndOfInput();
        }
        return bi.next() != BOOLEAN_FALSE;
    }

    @Override
    public boolean isNextType(int clazz, int number, boolean isConstructed) {
        try {
            return peekType() == (clazz | (isConstructed ? CONSTRUCTED_MASK : 0x00) | number);
        } catch (ASN1Exception e) {
            return false;
        }
    }

    @Override
    public int peekType() throws ASN1Exception {
        long currOffset = bi.getIndex();
        int tag = readTag();
        while ((bi.getIndex() != currOffset) && bi.hasPrevious()) {
            bi.previous();
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
            throw log.asnUnexpectedEndOfInput();
        }
    }

    @Override
    public boolean hasNextElement() {
        DecoderState lastState = states.peekLast();
        boolean hasNext;
        if (lastState != null) {
            hasNext = ((bi.getIndex() < lastState.getNextElementIndex()) && hasCompleteElement());
        } else {
            hasNext = hasCompleteElement();
        }
        return hasNext;
    }

    private  boolean hasCompleteElement() {
        boolean hasNext;
        long currOffset = bi.getIndex();
        try {
            readTag();
            int length = readLength();
            int i;
            for (i = 0; (i < length) && bi.hasNext(); i++) {
                bi.next();
            }
            hasNext = (i == length);
        } catch (ASN1Exception e) {
            hasNext = false;
        }
        while ((bi.getIndex() != currOffset) && bi.hasPrevious()) {
            bi.previous();
        }
        return hasNext;
    }

    @Override
    public byte[] drainElementValue() throws ASN1Exception {
        if (implicitTag != -1) {
            implicitTag = -1;
        }
        readTag();
        int length = readLength();
        byte[] value = new byte[length];
        if ((length != 0) && (bi.drain(value) != length)) {
            throw log.asnUnexpectedEndOfInput();
        }
        return value;
    }

    @Override
    public byte[] drainElement() throws ASN1Exception {
        if (implicitTag != -1) {
            implicitTag = -1;
        }
        long currOffset = bi.getIndex();
        readTag();
        int valueLength = readLength();
        int length = (int) ((bi.getIndex() - currOffset) + valueLength);
        while ((bi.getIndex() != currOffset) && bi.hasPrevious()) {
            bi.previous();
        }
        byte[] element = new byte[length];
        if ((length != 0) && (bi.drain(element) != length)) {
            throw log.asnUnexpectedEndOfInput();
        }
        return element;
    }

    @Override
    public byte[] drain() {
        return bi.drain();
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
                    throw log.asnInvalidHighTagNumberForm();
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
            throw log.asnUnexpectedEndOfInput();
        }
    }

    private void readTag(int expectedTag) throws ASN1Exception {
        if (implicitTag != -1) {
            expectedTag = implicitTag | (expectedTag & CONSTRUCTED_MASK);
            implicitTag = -1;
        }
        long currOffset = bi.getIndex();
        int actualTag = readTag();
        if (actualTag != expectedTag) {
            while ((bi.getIndex() != currOffset) && bi.hasPrevious()) {
                bi.previous();
            }
            throw log.asnUnexpectedTag();
        }
    }

    private int readLength() throws ASN1Exception {
        try {
            int length = bi.next();
            if (length > 127) {
                // Long form
                int numOctets = length & 0x7f;
                if (numOctets > 4) {
                    throw log.asnLengthEncodingExceeds4bytes();
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
            throw log.asnUnexpectedEndOfInput();
        }
    }

    /**
     * Decodes an OID and resolve its corresponding key algorithm.
     *
     * @return the key algorithm associated with the OID or null if no algorithm could be resolved
     */
    public String decodeObjectIdentifierAsKeyAlgorithm() {
        return keyAlgorithmFromOid(decodeObjectIdentifier());
    }

    /**
     * A class used to maintain state information during DER decoding.
     */
    static class DecoderState {
        // Tag number for a constructed element
        private final int tag;

        // The position of the first character in the encoded buffer that occurs after
        // the encoding of the constructed element
        private final long nextElementIndex;

        DecoderState(int tag, long nextElementIndex) {
            this.tag = tag;
            this.nextElementIndex = nextElementIndex;
        }

        public int getTag() {
            return tag;
        }

        public long getNextElementIndex() {
            return nextElementIndex;
        }
    }
}
