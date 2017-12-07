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
import static org.wildfly.security.asn1.util.ASN1.*;
import static org.wildfly.security.pem.Pem.extractDerContent;

import org.junit.Test;
import org.wildfly.common.iteration.CodePointIterator;
import org.wildfly.security.asn1.util.ASN1;

import java.util.ArrayList;

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
        assertTrue(decoder.hasNextElement());
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
        ArrayList<String> oidList = new ArrayList<String>();
        decoder.startSetOf();
        while (decoder.hasNextElement()) {
            assertEquals(OBJECT_IDENTIFIER_TYPE, decoder.peekType());
            oidList.add(decoder.decodeObjectIdentifier());
        }
        decoder.endSetOf();
        assertFalse(decoder.hasNextElement());
        assertEquals(3, oidList.size());
        assertEquals("1.2.123.1234", oidList.get(0));
        assertEquals("2.1.58.5456.36.456", oidList.get(1));
        assertEquals("1.2.459.14587.225466", oidList.get(2));
    }

    @Test
    public void testDecodeComplexSetOf() throws Exception {
        DERDecoder decoder = new DERDecoder(new byte[] {49, 82, 49, 28, 22, 11, 97, 98, 99, 64, 114, 115, 97, 46, 99, 111, 109, 22, 13, 116, 101, 115, 116, 49, 64, 114, 115, 97, 46, 99, 111, 109, 49, 50, 22, 16, 116, 104, 105, 115, 32, 105, 115, 32, 97, 32, 115, 116, 114, 105, 110, 103, 22, 30, 116, 104, 105, 115, 32, 105, 115, 32, 97, 32, 115, 116, 114, 105, 110, 103, 32, 116, 104, 97, 116, 39, 115, 32, 108, 111, 110, 103, 101, 114});
        assertEquals(SET_TYPE, decoder.peekType());
        ArrayList<String> strList = new ArrayList<String>();
        boolean firstSetSeen = false;
        decoder.startSetOf();
        while (decoder.hasNextElement()) {
            assertEquals(SET_TYPE, decoder.peekType());
            decoder.startSetOf();
            while (decoder.hasNextElement()) {
                assertEquals(IA5_STRING_TYPE, decoder.peekType());
                strList.add(decoder.decodeIA5String());
            }
            if (! firstSetSeen) {
                assertEquals(2, strList.size());
                firstSetSeen = true;
            }
            decoder.endSetOf();
        }
        decoder.endSetOf();
        assertFalse(decoder.hasNextElement());
        assertEquals(4, strList.size());
        assertEquals("abc@rsa.com", strList.get(0));
        assertEquals("test1@rsa.com", strList.get(1));
        assertEquals("this is a string", strList.get(2));
        assertEquals("this is a string that's longer", strList.get(3));
    }

    @Test
    public void testDecodeExplicitTag() throws Exception {
        DERDecoder decoder = new DERDecoder(new byte[] {-94, 43, 48, 41, 22, 14, 116, 104, 105, 115, 32, 105, 115, 32, 97, 32, 116, 101, 115, 116, 4, 8, 1, 35, 69, 103, -119, -85, -51, -17, 22, 13, 116, 101, 115, 116, 49, 64, 114, 115, 97, 46, 99, 111, 109});
        assertTrue(decoder.isNextType(CONTEXT_SPECIFIC_MASK, 2, true));
        decoder.startExplicit(2);
        assertTrue(decoder.hasNextElement());
        decoder.startSequence();
        assertTrue(decoder.hasNextElement());
        assertEquals("this is a test", decoder.decodeIA5String());
        assertArrayEquals(new byte[] {1, 35, 69, 103, -119, -85, -51, -17}, decoder.decodeOctetString());
        assertEquals("test1@rsa.com", decoder.decodeIA5String());
        assertFalse(decoder.hasNextElement());
        decoder.endSequence();
        assertFalse(decoder.hasNextElement());
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

    @Test
    public void testDecodeDrainElement() throws Exception {
        DERDecoder decoder = new DERDecoder(new byte[] {48, 26, -126, 19, 115, 101, 114, 118, 101, 114, 49, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, -124, 3, 42, 3, 4});
        decoder.startSequence();
        byte[] expected = new byte[] {-126, 19, 115, 101, 114, 118, 101, 114, 49, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109};
        assertArrayEquals(expected, decoder.drainElement());
        expected = new byte[] {-124, 3, 42, 3, 4};
        assertArrayEquals(expected, decoder.drainElement());
        decoder.endSequence();
        assertFalse(decoder.hasNextElement());
    }

    @Test
    public void testFormatDSAPublicKeyAsn1() throws Exception {
        String dsaPublicKey = "-----BEGIN PUBLIC KEY-----\n" +
                "MIIBuDCCASwGByqGSM44BAEwggEfAoGBAP1/U4EddRIpUt9KnC7s5Of2EbdSPO9E\n" +
                "AMMeP4C2USZpRV1AIlH7WT2NWPq/xfW6MPbLm1Vs14E7gB00b/JmYLdrmVClpJ+f\n" +
                "6AR7ECLCT7up1/63xhv4O1fnxqimFQ8E+4P208UewwI1VBNaFpEy9nXzrith1yrv\n" +
                "8iIDGZ3RSAHHAhUAl2BQjxUjC8yykrmCouuEC/BYHPUCgYEA9+GghdabPd7LvKtc\n" +
                "NrhXuXmUr7v6OuqC+VdMCz0HgmdRWVeOutRZT+ZxBxCBgLRJFnEj6EwoFhO3zwky\n" +
                "jMim4TwWeotUfI0o4KOuHiuzpnWRbqN/C/ohNWLx+2J6ASQ7zKTxvqhRkImog9/h\n" +
                "WuWfBpKLZl6Ae1UlZAFMO/7PSSoDgYUAAoGBAM5NVUxljeI2jZ9tQYhyyAZ9vy5c\n" +
                "gfvl2R1x+IbLWR84StLSQ07+Fu4Dj7Rr5Mh1DNVLuUtjRUyy1Mq5EkiIzuuAsv5a\n" +
                "9PCztH7rqV3Fgc0Yd48waOrcBDC9KjoI4bwH/Q1CcPynE6UOWxnaNNynIqQXYDfV\n" +
                "qnnkzohcaWf0mHnt\n" +
                "-----END PUBLIC KEY-----\n";

        byte[] der = extractDerContent(CodePointIterator.ofString(dsaPublicKey));
        String formatted = ASN1.formatAsn1(new DERDecoder(der));
        assertEquals("[sequence:[sequence:[oid:1.2.840.10040.4.1][sequence:[int:178011905478542266528237562450159990145232156369120674273274450314442865788737020770612695252123463079567156784778466449970650770920727857050009668388144034129745221171818506047231150039301079959358067395348717066319802262019714966524135060945913707594956514672855690606794135837542707371727429551343320695239][int:864205495604807476120572616017955259175325408501][int:174068207532402095185811980123523436538604490794561350978495831040599953488455823147851597408940950725307797094915759492368300574252438761037084473467180148876118103083043754985190983472601550494691329488083395492313850000361646482644608492304078721818959999056496097769368017749273708962006689187956744210730]]][bits:000000101000000110000001000000001100111001001101010101010100110001100101100011011110001000110110100011011001111101101101010000011000100001110010110010000000011001111101101111110010111001011100100000011111101111100101110110010001110101110001111110001000011011001011010110010001111100111000010010101101001011010010010000110100111011111110000101101110111000000011100011111011010001101011111001001100100001110101000011001101010101001011101110010100101101100011010001010100110010110010110101001100101010111001000100100100100010001000110011101110101110000000101100101111111001011010111101001111000010110011101101000111111011101011101010010101110111000101100000011100110100011000011101111000111100110000011010001110101011011100000001000011000010111101001010100011101000001000111000011011110000000111111111010000110101000010011100001111110010100111000100111010010100001110010110110001100111011010001101001101110010100111001000101010010000010111011000000011011111010101101010100111100111100100110011101000100001011100011010010110011111110100100110000111100111101101]]", formatted);
    }

    @Test
    public void testFormatRSAPublicKeyAsn1() throws Exception {
        String dsaPublicKey = "-----BEGIN PUBLIC KEY-----\n" +
                "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCJwvNh9/9zLIb1V0mI1VlbOml6\n" +
                "lopNYWwV1dl4F03rg2lXVMRbsRm+rQSyZeF5pUOWRe4O6U+2IZF1JJ4T1QZwpejJ\n" +
                "6AnBYnAI78HZwX7FCI8DWR81Wqk5aUpxaIWF88ciicOLJt5XW77IAeYDET8wh+gz\n" +
                "SQl9rF89HNQhZ0NyGwIDAQAB\n" +
                "-----END PUBLIC KEY-----\n";

        byte[] der = extractDerContent(CodePointIterator.ofString(dsaPublicKey));
        String formatted = ASN1.formatAsn1(new DERDecoder(der));
        assertEquals("[sequence:[sequence:[oid:1.2.840.113549.1.1.1][null]][bits:0011000010000001100010010000001010000001100000010000000010001001110000101111001101100001111101111111111101110011001011001000011011110101010101110100100110001000110101010101100101011011001110100110100101111010100101101000101001001101011000010110110000010101110101011101100101111000000101110100110111101011100000110110100101010111010101001100010001011011101100010001100110111110101011010000010010110010011001011110000101111001101001010100001110010110010001011110111000001110111010010100111110110110001000011001000101110101001001001001111000010011110101010000011001110000101001011110100011001001111010000000100111000001011000100111000000001000111011111100000111011001110000010111111011000101000010001000111100000011010110010001111100110101010110101010100100111001011010010100101001110001011010001000010110000101111100111100011100100010100010011100001110001011001001101101111001010111010110111011111011001000000000011110011000000011000100010011111100110000100001111110100000110011010010010000100101111101101011000101111100111101000111001101010000100001011001110100001101110010000110110000001000000011000000010000000000000001]]", formatted);
    }

    @Test
    public void testFormatECPublicKeyAsn1() throws Exception {
        String dsaPublicKey = "-----BEGIN PUBLIC KEY-----\n" +
                "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4r0DR0jxgNK4RGCpXrpS8qXot2/3\n" +
                "YtoGAW5fLU7+93mHRBNyW16JWUYH9RDa7igYb29MpIzX6w82cgt494xn/g==\n" +
                "-----END PUBLIC KEY-----\n";

        byte[] der = extractDerContent(CodePointIterator.ofString(dsaPublicKey));
        String formatted = ASN1.formatAsn1(new DERDecoder(der));
        assertEquals("[sequence:[sequence:[oid:1.2.840.10045.2.1][oid:1.2.840.10045.3.1.7]][bits:0000010011100010101111010000001101000111010010001111000110000000110100101011100001000100011000001010100101011110101110100101001011110010101001011110100010110111011011111111011101100010110110100000011000000001011011100101111100101101010011101111111011110111011110011000011101000100000100110111001001011011010111101000100101011001010001100000011111110101000100001101101011101110001010000001100001101111011011110100110010100100100011001101011111101011000011110011011001110010000010110111100011110111100011000110011111111110]]", formatted);
    }

    @Test
    public void testDecodeLongFormLength() throws Exception {
        DERDecoder decoder = new DERDecoder(new byte[] {49, -127, -79, 48, -127, -82, 4, 86, 48, 84, 22, 11, 116, 101, 115, 116, 32, 115, 116, 114, 105, 110, 103, 4, 8, 1, 35, 69, 103, -119, -85, -51, -17, 49, 59, 4, 8, 1, 35, 69, 103, -119, -85, -51, -17, 48, 16, 22, 7, 116, 101, 115, 116, 105, 110, 103, 22, 5, 97, 103, 97, 105, 110, 22, 14, 116, 104, 105, 115, 32, 105, 115, 32, 97, 32, 116, 101, 115, 116, 22, 13, 116, 101, 115, 116, 49, 64, 114, 115, 97, 46, 99, 111, 109, 4, 84, 49, 82, 49, 28, 22, 11, 97, 98, 99, 64, 114, 115, 97, 46, 99, 111, 109, 22, 13, 116, 101, 115, 116, 49, 64, 114, 115, 97, 46, 99, 111, 109, 49, 50, 22, 16, 116, 104, 105, 115, 32, 105, 115, 32, 97, 32, 115, 116, 114, 105, 110, 103, 22, 30, 116, 104, 105, 115, 32, 105, 115, 32, 97, 32, 115, 116, 114, 105, 110, 103, 32, 116, 104, 97, 116, 39, 115, 32, 108, 111, 110, 103, 101, 114});
        decoder.startSetOf();
        decoder.startSequence();
        byte[] expected = new byte[] {48, 84, 22, 11, 116, 101, 115, 116, 32, 115, 116, 114, 105, 110, 103, 4, 8, 1, 35, 69, 103, -119, -85, -51, -17,  49, 59, 4, 8, 1, 35, 69, 103, -119, -85, -51, -17, 48, 16, 22, 7, 116, 101, 115, 116, 105, 110, 103, 22, 5, 97, 103, 97, 105, 110, 22, 14, 116, 104, 105, 115, 32, 105, 115, 32, 97, 32, 116, 101, 115, 116, 22, 13, 116, 101, 115, 116, 49, 64, 114, 115, 97, 46, 99, 111, 109};
        assertArrayEquals(expected, decoder.drainElementValue());
        expected = new byte[] {49, 82, 49, 28, 22, 11, 97, 98, 99, 64, 114, 115, 97, 46, 99, 111, 109, 22, 13, 116, 101, 115, 116, 49, 64, 114, 115, 97, 46, 99, 111, 109, 49, 50, 22, 16, 116, 104, 105, 115, 32, 105, 115, 32, 97, 32, 115, 116, 114, 105, 110, 103, 22, 30, 116, 104, 105, 115, 32, 105, 115, 32, 97, 32, 115, 116, 114, 105, 110, 103, 32, 116, 104, 97, 116, 39, 115, 32, 108, 111, 110, 103, 101, 114};
        assertArrayEquals(expected, decoder.drainElementValue());
        decoder.endSequence();
        decoder.endSetOf();
        assertFalse(decoder.hasNextElement());
    }

    @Test
    public void testDecodeBoolean() throws Exception {
        DERDecoder decoder = new DERDecoder(new byte[] {1, 1, -1});
        assertTrue(decoder.decodeBoolean());

        decoder = new DERDecoder(new byte[] {1, 1, 0});
        assertFalse(decoder.decodeBoolean());
    }
}
