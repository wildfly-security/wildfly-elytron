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

import static org.junit.Assert.*;
import static org.wildfly.security.asn1.ASN1.*;

import org.junit.Test;

/**
 * Tests for DER decoding.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public class DERDecoderTest {

    @Test
    public void testDecodeEmptyOctetString() throws Exception {
        // As byte array
        DERDecoder decoder = new DERDecoder(new byte[] {4, 0});
        assertArrayEquals(new byte[0], decoder.decodeOctetString());

        // As string
        decoder = new DERDecoder(new byte[] {4, 0});
        assertEquals("", decoder.decodeOctetStringAsString());
    }

    @Test
    public void testDecodeOctetString() throws Exception {
        DERDecoder decoder = new DERDecoder(new byte[] {4, 13, 97, 98, 99, 100, 33, 35, 69, 70, 71, 72, 32, 94, 94});
        assertArrayEquals(new byte[] {97, 98, 99, 100, 33, 35, 69, 70, 71, 72, 32, 94, 94}, decoder.decodeOctetString());
    }

    @Test
    public void testDecodeOctetStringAsString() throws Exception {
        DERDecoder decoder = new DERDecoder(new byte[] {4, 20, -61, -124, -61, -92, -61, -117, -61, -85, -61, -113, -61, -81, -61, -106, -61, -74, -61, -100, -61, -68});
        assertEquals("ÄäËëÏïÖöÜü", decoder.decodeOctetStringAsString());
        decoder = new DERDecoder(new byte[] { 4, 10, -60, -28, -53, -21, -49, -17, -42, -10, -36, -4 });
        assertEquals("ÄäËëÏïÖöÜü", decoder.decodeOctetStringAsString("ISO-8859-1"));
    }

    @Test
    public void testDecodeEmptyIA5String() throws Exception {
        // As string
        DERDecoder decoder = new DERDecoder(new byte[] {22, 0});
        assertEquals("", decoder.decodeIA5String());

        // As byte array
        decoder = new DERDecoder(new byte[] {22, 0});
        assertArrayEquals(new byte[0], decoder.decodeIA5StringAsBytes());
    }

    @Test
    public void testDecodeIA5String() throws Exception {
        DERDecoder decoder = new DERDecoder(new byte[] {22, 13, 116, 101, 115, 116, 49, 64, 114, 115, 97, 46, 99, 111, 109});
        assertEquals("test1@rsa.com", decoder.decodeIA5String());

        decoder = new DERDecoder(new byte[] {22, 13, 116, 101, 115, 116, 49, 64, 114, 115, 97, 46, 99, 111, 109});
        assertArrayEquals(new byte[] {116, 101, 115, 116, 49, 64, 114, 115, 97, 46, 99, 111, 109}, decoder.decodeIA5StringAsBytes());
    }

    @Test
    public void testDecodeEmptyBitString() throws Exception {
        // Decode as a byte array
        DERDecoder decoder = new DERDecoder(new byte[] {3, 1, 0});
        assertArrayEquals(new byte[] {}, decoder.decodeBitString());

        // Decode as a binary string
        decoder = new DERDecoder(new byte[] {3, 1, 0});
        assertEquals("", decoder.decodeBitStringAsString());
    }

    @Test
    public void testDecodeBitString() throws Exception {
        // With unused bits present
        DERDecoder decoder = new DERDecoder(new byte[] {3, 4, 6, 110, 93, -64});
        byte[] expected = new byte[] {1, -71, 119};
        assertArrayEquals(expected, decoder.decodeBitString());

        // Without unused bits
        decoder = new DERDecoder(new byte[] {3, 4, 0, 110, 93, -64});
        expected = new byte[] {110, 93, -64};
        assertArrayEquals(expected, decoder.decodeBitString());

    }

    @Test
    public void testDecodeBitStringAsString() throws Exception {
        // With unused bits present
        DERDecoder decoder = new DERDecoder(new byte[] {3, 4, 6, 110, 93, -64});
        assertEquals("011011100101110111", decoder.decodeBitStringAsString());

        // Without unused bits
        decoder = new DERDecoder(new byte[] {3, 4, 0, 110, 93, -64});
        assertEquals("011011100101110111000000", decoder.decodeBitStringAsString());
    }

    @Test(expected=ASN1Exception.class)
    public void testDecodeInvalidBitString() throws Exception {
        DERDecoder decoder = new DERDecoder(new byte[] {3, 4, 8, 110, 93, -64});
        decoder.decodeBitStringAsString();
    }

    @Test
    public void testDecodeObjectIdentifier() throws Exception {
        DERDecoder decoder = new DERDecoder(new byte[] {6, 21, 105, -126, -89, -33, -76, -24, -97, -72, -72, -57, -75, -94, -46, -64, -128, -86, -82, -41, -118, 27, 1});
        assertEquals("2.25.196556539987194312349856245628873852187.1", decoder.decodeObjectIdentifier());
    }

    @Test
    public void testDecodeNull() throws Exception {
        DERDecoder decoder = new DERDecoder(new byte[] {5, 0});
        decoder.decodeNull();
        assertFalse(decoder.hasNextElement());
    }

    @Test(expected=ASN1Exception.class)
    public void testDecodeInvalidNull() throws Exception {
        DERDecoder decoder = new DERDecoder(new byte[] {5, 12});
        decoder.decodeNull();
    }

    @Test(expected=IllegalStateException.class)
    public void testDecodeEndSequenceBeforeStart() throws Exception {
        DERDecoder decoder = new DERDecoder(new byte[] {48, 41, 22, 14, 116, 104, 105, 115, 32, 105, 115, 32, 97, 32, 116, 101, 115, 116, 4, 8, 1, 35, 69, 103, -119, -85, -51, -17, 22, 13, 116, 101, 115, 116, 49, 64, 114, 115, 97, 46, 99, 111, 109});
        decoder.endSequence();
    }

    @Test(expected=IllegalStateException.class)
    public void testDecodeEndSetBeforeStart() throws Exception {
        DERDecoder decoder = new DERDecoder(new byte[] {49, 28, 4, 8, 1, 35, 69, 103, -119, -85, -51, -17, 4, 3, 1, 35, 69, 5, 0, 6, 9, 42, -126, -28, 116, -108, -91, -31, -90, 38});
        decoder.endSet();
    }

    @Test(expected=IllegalStateException.class)
    public void testDecodeEndExplicitBeforeStart() throws Exception {
        DERDecoder decoder = new DERDecoder(new byte[] {-94, 43, 48, 41, 22, 14, 116, 104, 105, 115, 32, 105, 115, 32, 97, 32, 116, 101, 115, 116, 4, 8, 1, 35, 69, 103, -119, -85, -51, -17, 22, 13, 116, 101, 115, 116, 49, 64, 114, 115, 97, 46, 99, 111, 109});
        decoder.endExplicit();
    }

    @Test
    public void testDecodeSimpleSequence() throws Exception {
        DERDecoder decoder = new DERDecoder(new byte[] {48, 41, 22, 14, 116, 104, 105, 115, 32, 105, 115, 32, 97, 32, 116, 101, 115, 116, 4, 8, 1, 35, 69, 103, -119, -85, -51, -17, 22, 13, 116, 101, 115, 116, 49, 64, 114, 115, 97, 46, 99, 111, 109});
        assertTrue(decoder.hasNextElement());
        decoder.startSequence();
        assertTrue(decoder.hasNextElement());
        assertEquals("this is a test", decoder.decodeIA5String());
        assertTrue(decoder.hasNextElement());
        assertArrayEquals(new byte[] {1, 35, 69, 103, -119, -85, -51, -17}, decoder.decodeOctetString());
        assertTrue(decoder.hasNextElement());
        assertEquals("test1@rsa.com", decoder.decodeIA5String());
        assertFalse(decoder.hasNextElement());
        decoder.endSequence();
        assertFalse(decoder.hasNextElement());
    }

    @Test
    public void testDecodeComplexSequence() throws Exception {
        DERDecoder decoder = new DERDecoder(new byte[] {48, 93, 22, 11, 116, 101, 115, 116, 32, 115, 116, 114, 105, 110, 103, 4, 8, 1, 35, 69, 103, -119, -85, -51, -17, 48, 59, 22, 14, 116, 104, 105, 115, 32, 105, 115, 32, 97, 32, 116, 101, 115, 116, 4, 8, 1, 35, 69, 103, -119, -85, -51, -17, 48, 16, 22, 7, 116, 101, 115, 116, 105, 110, 103, 22, 5, 97, 103, 97, 105, 110, 22, 13, 116, 101, 115, 116, 49, 64, 114, 115, 97, 46, 99, 111, 109, 22, 7, 116, 104, 101, 32, 101, 110, 100});
        decoder.startSequence();
        assertEquals("test string", decoder.decodeIA5String());
        assertArrayEquals(new byte[]{1, 35, 69, 103, -119, -85, -51, -17}, decoder.decodeOctetString());
        decoder.startSequence();
        assertEquals("this is a test", decoder.decodeIA5String());
        assertArrayEquals(new byte[] {1, 35, 69, 103, -119, -85, -51, -17}, decoder.decodeOctetString());
        decoder.startSequence();
        // Skip over the two elements in this sequence
        decoder.endSequence();
        assertEquals("test1@rsa.com", decoder.decodeIA5String());
        decoder.endSequence();
        assertEquals("the end", decoder.decodeIA5String());
        decoder.endSequence();
    }

    @Test
    public void testDecodeSimpleSet() throws Exception {
        DERDecoder decoder = new DERDecoder(new byte[] {49, 28, 4, 8, 1, 35, 69, 103, -119, -85, -51, -17, 4, 3, 1, 35, 69, 5, 0, 6, 9, 42, -126, -28, 116, -108, -91, -31, -90, 38});
        assertEquals(SET_TYPE, decoder.peekType());
        decoder.startSet();
        assertEquals(OCTET_STRING_TYPE, decoder.peekType());
        assertArrayEquals(new byte[] {1, 35, 69, 103, -119, -85, -51, -17}, decoder.decodeOctetString());
        assertEquals(OCTET_STRING_TYPE, decoder.peekType());
        assertArrayEquals(new byte[] {1, 35, 69}, decoder.decodeOctetString());
        assertEquals(NULL_TYPE, decoder.peekType());
        decoder.decodeNull();
        assertEquals(OBJECT_IDENTIFIER_TYPE, decoder.peekType());
        assertEquals("1.2.45684.5447897894", decoder.decodeObjectIdentifier());
        decoder.endSet();
    }

    @Test
    public void testDecodeComplexSet() throws Exception {
        DERDecoder decoder = new DERDecoder(new byte[] {49, 67, 4, 8, 1, 35, 69, 103, -119, -85, -51, -17, 6, 4, 42, 123, -119, 82, 49, 34, 4, 3, 1, 35, 69, 5, 0, 6, 5, 81, 58, -86, 80, 36, 49, 18, 5, 0, 22, 14, 116, 104, 105, 115, 32, 105, 115, 32, 97, 32, 116, 101, 115, 116, 22, 13, 116, 101, 115, 116, 49, 64, 114, 115, 97, 46, 99, 111, 109});
        assertEquals(SET_TYPE, decoder.peekType());
        decoder.startSet();
        assertEquals(OCTET_STRING_TYPE, decoder.peekType());
        decoder.skipElement();
        assertEquals(OBJECT_IDENTIFIER_TYPE, decoder.peekType());
        decoder.skipElement();
        assertEquals(SET_TYPE, decoder.peekType());
        decoder.startSet();
        assertEquals(OCTET_STRING_TYPE, decoder.peekType());
        decoder.skipElement();
        assertEquals(NULL_TYPE, decoder.peekType());
        decoder.skipElement();
        assertEquals(OBJECT_IDENTIFIER_TYPE, decoder.peekType());
        decoder.skipElement();
        assertEquals(SET_TYPE, decoder.peekType());
        decoder.skipElement();
        decoder.endSet();
        assertEquals(IA5_STRING_TYPE, decoder.peekType());
        decoder.skipElement();
    }

    @Test
    public void testDecodeSimpleSetOf() throws Exception {
        DERDecoder decoder = new DERDecoder(new byte[] {49, 25, 6, 4, 42, 123, -119, 82, 6, 7, 81, 58, -86, 80, 36, -125, 72, 6, 8, 42, -125, 75, -15, 123, -115, -31, 58});
        assertEquals(SET_TYPE, decoder.peekType());
        decoder.startSetOf();
        assertEquals(OBJECT_IDENTIFIER_TYPE, decoder.peekType());
        assertEquals("1.2.123.1234", decoder.decodeObjectIdentifier());
        assertEquals(OBJECT_IDENTIFIER_TYPE, decoder.peekType());
        assertEquals("2.1.58.5456.36.456", decoder.decodeObjectIdentifier());
        assertEquals(OBJECT_IDENTIFIER_TYPE, decoder.peekType());
        assertEquals("1.2.459.14587.225466", decoder.decodeObjectIdentifier());
        decoder.endSetOf();
    }

    @Test
    public void testDecodeComplexSetOf() throws Exception {
        DERDecoder decoder = new DERDecoder(new byte[] {49, 82, 49, 28, 22, 11, 97, 98, 99, 64, 114, 115, 97, 46, 99, 111, 109, 22, 13, 116, 101, 115, 116, 49, 64, 114, 115, 97, 46, 99, 111, 109, 49, 50, 22, 16, 116, 104, 105, 115, 32, 105, 115, 32, 97, 32, 115, 116, 114, 105, 110, 103, 22, 30, 116, 104, 105, 115, 32, 105, 115, 32, 97, 32, 115, 116, 114, 105, 110, 103, 32, 116, 104, 97, 116, 39, 115, 32, 108, 111, 110, 103, 101, 114});
        assertEquals(SET_TYPE, decoder.peekType());
        decoder.startSetOf();
        assertEquals(SET_TYPE, decoder.peekType());
        decoder.startSetOf();
        assertEquals(IA5_STRING_TYPE, decoder.peekType());
        decoder.skipElement();
        assertEquals(IA5_STRING_TYPE, decoder.peekType());
        decoder.endSetOf();
        decoder.startSetOf();
        assertEquals(IA5_STRING_TYPE, decoder.peekType());
        decoder.skipElement();
        assertEquals(IA5_STRING_TYPE, decoder.peekType());
        decoder.endSetOf();
        decoder.endSetOf();
        assertFalse(decoder.hasNextElement());
    }

    @Test
    public void testDecodeExplicitTag() throws Exception {
        DERDecoder decoder = new DERDecoder(new byte[] {-94, 43, 48, 41, 22, 14, 116, 104, 105, 115, 32, 105, 115, 32, 97, 32, 116, 101, 115, 116, 4, 8, 1, 35, 69, 103, -119, -85, -51, -17, 22, 13, 116, 101, 115, 116, 49, 64, 114, 115, 97, 46, 99, 111, 109});
        assertTrue(decoder.isNextType(CONTEXT_SPECIFIC_MASK, 2, true));
        decoder.startExplicit(2);
        decoder.startSequence();
        assertEquals("this is a test", decoder.decodeIA5String());
        assertArrayEquals(new byte[] {1, 35, 69, 103, -119, -85, -51, -17}, decoder.decodeOctetString());
        assertEquals("test1@rsa.com", decoder.decodeIA5String());
        decoder.endSequence();
        decoder.endExplicit();
        assertFalse(decoder.hasNextElement());
    }

    @Test
    public void testDecodeImplicitTag() throws Exception {
        DERDecoder decoder = new DERDecoder(new byte[] {-126, 19, 115, 101, 114, 118, 101, 114, 49, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109});
        assertFalse(decoder.isNextType(CONTEXT_SPECIFIC_MASK, 0, false));
        assertFalse(decoder.isNextType(CONTEXT_SPECIFIC_MASK, 1, true));
        assertTrue(decoder.isNextType(CONTEXT_SPECIFIC_MASK, 2, false));
        decoder.decodeImplicit(2);
        assertEquals("server1.example.com", decoder.decodeIA5String());
    }

    @Test(expected=ASN1Exception.class)
    public void testDecodeWrongType() throws Exception {
        DERDecoder decoder = new DERDecoder(new byte[] {5, 12});
        decoder.decodeIA5String();
    }

    @Test
    public void testDecodeRecoverAfterWrongType() throws Exception {
        DERDecoder decoder = new DERDecoder(new byte[] {22, 13, 116, 101, 115, 116, 49, 64, 114, 115, 97, 46, 99, 111, 109});
        try {
            decoder.decodeOctetString();
        } catch (ASN1Exception e) {
            assertTrue(decoder.hasNextElement());
            assertEquals(IA5_STRING_TYPE, decoder.peekType());
            assertEquals("test1@rsa.com", decoder.decodeIA5String());
        }
    }

    @Test
    public void testDecodeDrainElementValue() throws Exception {
        DERDecoder decoder = new DERDecoder(new byte[] {49, 25, 6, 4, 42, 123, -119, 82, 6, 7, 81, 58, -86, 80, 36, -125, 72, 6, 8, 42, -125, 75, -15, 123, -115, -31, 58});
        assertEquals(SET_TYPE, decoder.peekType());
        assertTrue(decoder.hasNextElement());
        byte[] expected = new byte[] {6, 4, 42, 123, -119, 82, 6, 7, 81, 58, -86, 80, 36, -125, 72, 6, 8, 42, -125, 75, -15, 123, -115, -31, 58};
        assertArrayEquals(expected, decoder.drainElementValue());
        assertFalse(decoder.hasNextElement());
    }
}
