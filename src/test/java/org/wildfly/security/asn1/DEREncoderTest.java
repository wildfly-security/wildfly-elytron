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

import org.junit.Test;
import org.wildfly.security.sasl.util.ByteStringBuilder;

/**
 * Tests for DER encoding. The expected results for these test cases were generated using
 * Bouncy Castle's and Sun's DER libraries.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public class DEREncoderTest {

    @Test
    public void testEncodeEmptyOctetString() throws Exception {
        ByteStringBuilder target = new ByteStringBuilder();
        DEREncoder encoder = new DEREncoder(target);
        encoder.encodeOctetString("");
        assertArrayEquals(new byte[] {4, 0}, target.toArray());

        target = new ByteStringBuilder();
        encoder = new DEREncoder(target);
        encoder.encodeOctetString(new ByteStringBuilder());
        assertArrayEquals(new byte[] {4, 0}, target.toArray());

        target = new ByteStringBuilder();
        encoder = new DEREncoder(target);
        encoder.encodeOctetString(new byte[0]);
        assertArrayEquals(new byte[] {4, 0}, target.toArray());
    }

    @Test
    public void testEncodeOctetString() throws Exception {
        ByteStringBuilder target = new ByteStringBuilder();
        DEREncoder encoder = new DEREncoder(target);
        encoder.encodeOctetString(new byte[] {1, 35, 69, 103, -119, -85, -51, -17});
        byte[] expected = new byte[] {4, 8, 1, 35, 69, 103, -119, -85, -51, -17};
        assertArrayEquals(expected, target.toArray());
    }

    @Test
    public void testEncodeEmptyIA5String() throws Exception {
        ByteStringBuilder target = new ByteStringBuilder();
        DEREncoder encoder = new DEREncoder(target);
        encoder.encodeIA5String(new byte[0]);
        assertArrayEquals(new byte[] {22, 0}, target.toArray());

        target = new ByteStringBuilder();
        encoder = new DEREncoder(target);
        encoder.encodeIA5String(new ByteStringBuilder());
        assertArrayEquals(new byte[] {22, 0}, target.toArray());

        target = new ByteStringBuilder();
        encoder = new DEREncoder(target);
        encoder.encodeIA5String("");
        assertArrayEquals(new byte[] {22, 0}, target.toArray());
    }

    @Test
    public void testEncodeIA5String() throws Exception {
        ByteStringBuilder target = new ByteStringBuilder();
        DEREncoder encoder = new DEREncoder(target);
        encoder.encodeIA5String("test1@rsa.com");
        byte[] expected = new byte[] {22, 13, 116, 101, 115, 116, 49, 64, 114, 115, 97, 46, 99, 111, 109};
        assertArrayEquals(expected, target.toArray());
    }

    @Test
    public void testEncodeEmptyBitString() throws Exception {
        ByteStringBuilder target = new ByteStringBuilder();
        DEREncoder encoder = new DEREncoder(target);
        encoder.encodeBitString(new byte[] {}, 0);
        byte[] expected = new byte[] {3, 1, 0};
        assertArrayEquals(expected, target.toArray());

        target = new ByteStringBuilder();
        encoder = new DEREncoder(target);
        encoder.encodeBitString("");
        assertArrayEquals(new byte[] {3, 1, 0}, target.toArray());
    }

    @Test
    public void testEncodeBitString() throws Exception {
        ByteStringBuilder target = new ByteStringBuilder();
        DEREncoder encoder = new DEREncoder(target);
        encoder.encodeBitString(new byte[] {110, 93, -64}, 6);
        byte[] expected = new byte[] {3, 4, 6, 110, 93, -64};
        assertArrayEquals(expected, target.toArray());
    }

    @Test
    public void testEncodeBitStringUsingBinaryString() throws Exception {
        ByteStringBuilder target = new ByteStringBuilder();
        DEREncoder encoder = new DEREncoder(target);
        encoder.encodeBitString("011011100101110111");
        byte[] expected = new byte[] {(byte)0x03, (byte)0x04, (byte)0x06, (byte)0x6e, (byte)0x5d, (byte)0xc0};
        assertArrayEquals(expected, target.toArray());
    }

    @Test
    public void testEncodeObjectIdentifier() throws Exception {
        ByteStringBuilder target = new ByteStringBuilder();
        DEREncoder encoder = new DEREncoder(target);
        encoder.encodeObjectIdentifier("2.25.196556539987194312349856245628873852187.1.128");
        byte[] expected = {6, 23, 105, -126, -89, -33, -76, -24, -97, -72, -72, -57, -75, -94, -46, -64, -128, -86, -82, -41, -118, 27, 1, -127, 0};
        assertArrayEquals(expected, target.toArray());
    }

    @Test(expected=ASN1Exception.class)
    public void testEncodeObjectIdentifierTooFewComponents() throws Exception {
        ByteStringBuilder target = new ByteStringBuilder();
        DEREncoder encoder = new DEREncoder(target);
        encoder.encodeObjectIdentifier("1");
    }

    @Test(expected=ASN1Exception.class)
    public void testEncodeObjectIdentifierInvalidFirstComponent() throws Exception {
        ByteStringBuilder target = new ByteStringBuilder();
        DEREncoder encoder = new DEREncoder(target);
        encoder.encodeObjectIdentifier("5.10");
    }

    @Test(expected=ASN1Exception.class)
    public void testEncodeObjectIdentifierInvalidSecondComponent() throws Exception {
        ByteStringBuilder target = new ByteStringBuilder();
        DEREncoder encoder = new DEREncoder(target);
        encoder.encodeObjectIdentifier("0.50");
    }

    @Test
    public void testEncodeNull() throws Exception {
        ByteStringBuilder target = new ByteStringBuilder();
        DEREncoder encoder = new DEREncoder(target);
        encoder.encodeNull();
        byte[] expected = {5, 0};
        assertArrayEquals(expected, target.toArray());
    }

    @Test(expected=IllegalStateException.class)
    public void testEncodeEndSequenceBeforeStart() throws Exception {
        ByteStringBuilder target = new ByteStringBuilder();
        DEREncoder encoder = new DEREncoder(target);
        encoder.endSequence();
    }

    @Test(expected=IllegalStateException.class)
    public void testEncodeEndSetBeforeStart() throws Exception {
        ByteStringBuilder target = new ByteStringBuilder();
        DEREncoder encoder = new DEREncoder(target);
        encoder.endSequence();
    }

    @Test
    public void testEncodeSimpleSequence() throws Exception {
        ByteStringBuilder target = new ByteStringBuilder();
        DEREncoder encoder = new DEREncoder(target);
        encoder.startSequence();
        encoder.encodeIA5String("this is a test");
        encoder.encodeOctetString(new byte[] {1, 35, 69, 103, -119, -85, -51, -17});
        encoder.encodeIA5String("test1@rsa.com");
        encoder.endSequence();
        byte[] expected = new byte[] {48, 41, 22, 14, 116, 104, 105, 115, 32, 105, 115, 32, 97, 32, 116, 101, 115, 116, 4, 8, 1, 35, 69, 103, -119, -85, -51, -17, 22, 13, 116, 101, 115, 116, 49, 64, 114, 115, 97, 46, 99, 111, 109};
        assertArrayEquals(expected, target.toArray());
    }

    @Test
    public void testEncodeComplexSequence() throws Exception {
        ByteStringBuilder target = new ByteStringBuilder();
        DEREncoder encoder = new DEREncoder(target);

        encoder.startSequence();

        encoder.encodeIA5String("test string");
        encoder.encodeOctetString(new byte[]{1, 35, 69, 103, -119, -85, -51, -17});

        encoder.startSequence();
        encoder.encodeIA5String("this is a test");
        encoder.encodeOctetString(new byte[] {1, 35, 69, 103, -119, -85, -51, -17});

        encoder.startSequence();
        encoder.encodeIA5String("testing");
        encoder.encodeIA5String("again");
        encoder.endSequence();

        encoder.encodeIA5String("test1@rsa.com");
        encoder.endSequence();

        encoder.encodeIA5String("the end");

        encoder.endSequence();

        byte[] expected = new byte[] {48, 93, 22, 11, 116, 101, 115, 116, 32, 115, 116, 114, 105, 110, 103, 4, 8, 1, 35, 69, 103, -119, -85, -51, -17, 48, 59, 22, 14, 116, 104, 105, 115, 32, 105, 115, 32, 97, 32, 116, 101, 115, 116, 4, 8, 1, 35, 69, 103, -119, -85, -51, -17, 48, 16, 22, 7, 116, 101, 115, 116, 105, 110, 103, 22, 5, 97, 103, 97, 105, 110, 22, 13, 116, 101, 115, 116, 49, 64, 114, 115, 97, 46, 99, 111, 109, 22, 7, 116, 104, 101, 32, 101, 110, 100};
        assertArrayEquals(expected, target.toArray());
    }

    @Test
    public void testEncodeSimpleSet() throws Exception {
        ByteStringBuilder target = new ByteStringBuilder();
        DEREncoder encoder = new DEREncoder(target);
        encoder.startSet();
        encoder.encodeNull();
        encoder.encodeOctetString(new byte[] {1, 35, 69, 103, -119, -85, -51, -17});
        encoder.encodeObjectIdentifier("1.2.45684.5447897894");
        encoder.encodeOctetString(new byte[] {1, 35, 69});
        encoder.endSet();
        byte[] expected = new byte[] {49, 28, 4, 8, 1, 35, 69, 103, -119, -85, -51, -17, 4, 3, 1, 35, 69, 5, 0, 6, 9, 42, -126, -28, 116, -108, -91, -31, -90, 38};
        assertArrayEquals(expected, target.toArray());
    }

    @Test
    public void testEncodeComplexSet() throws Exception {
        ByteStringBuilder target = new ByteStringBuilder();
        DEREncoder encoder = new DEREncoder(target);

        encoder.startSet();

        encoder.encodeObjectIdentifier("1.2.123.1234");
        encoder.encodeOctetString(new byte[]{1, 35, 69, 103, -119, -85, -51, -17});

        encoder.startSet();
        encoder.encodeObjectIdentifier("2.1.58.5456.36");
        encoder.encodeOctetString(new byte[] {1, 35, 69});

        encoder.startSet();
        encoder.encodeNull();
        encoder.encodeIA5String("this is a test");
        encoder.endSet();

        encoder.encodeNull();
        encoder.endSet();

        encoder.encodeIA5String("test1@rsa.com");
        encoder.endSet();

        byte[] expected = new byte[] { 49, 67, 4, 8, 1, 35, 69, 103, -119, -85, -51, -17, 6, 4, 42, 123, -119, 82, 49, 34, 4, 3, 1, 35, 69, 5, 0, 6, 5, 81, 58, -86, 80, 36, 49, 18, 5, 0, 22, 14, 116, 104, 105, 115, 32, 105, 115, 32, 97, 32, 116, 101, 115, 116, 22, 13, 116, 101, 115, 116, 49, 64, 114, 115, 97, 46, 99, 111, 109 };
        assertArrayEquals(expected, target.toArray());
    }

    @Test
    public void testEncodeSimpleSetOf() throws Exception {
        ByteStringBuilder target = new ByteStringBuilder();
        DEREncoder encoder = new DEREncoder(target);

        encoder.startSetOf();
        encoder.encodeObjectIdentifier("1.2.459.14587.225466");
        encoder.encodeObjectIdentifier("1.2.123.1234");
        encoder.encodeObjectIdentifier("2.1.58.5456.36.456");
        encoder.endSetOf();

        byte[] expected = new byte[] {49, 25, 6, 4, 42, 123, -119, 82, 6, 7, 81, 58, -86, 80, 36, -125, 72, 6, 8, 42, -125, 75, -15, 123, -115, -31, 58};
        assertArrayEquals(expected, target.toArray());
    }

    @Test
    public void testEncodeComplexSetOf() throws Exception {
        ByteStringBuilder target = new ByteStringBuilder();
        DEREncoder encoder = new DEREncoder(target);

        encoder.startSetOf();

        encoder.startSetOf();
        encoder.encodeIA5String("test1@rsa.com");
        encoder.encodeIA5String("abc@rsa.com");
        encoder.endSetOf();

        encoder.startSetOf();
        encoder.encodeIA5String("this is a string that's longer");
        encoder.encodeIA5String("this is a string");
        encoder.endSetOf();

        encoder.endSetOf();

        byte[] expected = new byte[] {49, 82, 49, 28, 22, 11, 97, 98, 99, 64, 114, 115, 97, 46, 99, 111, 109, 22, 13, 116, 101, 115, 116, 49, 64, 114, 115, 97, 46, 99, 111, 109, 49, 50, 22, 16, 116, 104, 105, 115, 32, 105, 115, 32, 97, 32, 115, 116, 114, 105, 110, 103, 22, 30, 116, 104, 105, 115, 32, 105, 115, 32, 97, 32, 115, 116, 114, 105, 110, 103, 32, 116, 104, 97, 116, 39, 115, 32, 108, 111, 110, 103, 101, 114};
        assertArrayEquals(expected, target.toArray());
    }

    @Test
    public void testEncodeImplicit() throws Exception {
        ByteStringBuilder target = new ByteStringBuilder();
        DEREncoder encoder = new DEREncoder(target);
        encoder.encodeImplicit(2);
        encoder.encodeIA5String("server1.example.com");
        byte[] expected = new byte[] {-126, 19, 115, 101, 114, 118, 101, 114, 49, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109};
        assertArrayEquals(expected, target.toArray());
    }

    @Test
    public void testFlush() throws Exception {
        ByteStringBuilder target = new ByteStringBuilder();
        DEREncoder encoder = new DEREncoder(target);

        encoder.startSequence();

        encoder.encodeIA5String("test string");
        encoder.encodeOctetString(new byte[]{1, 35, 69, 103, -119, -85, -51, -17});

        encoder.startSet();
        encoder.encodeIA5String("this is a test");
        encoder.encodeOctetString(new byte[] {1, 35, 69, 103, -119, -85, -51, -17});

        encoder.startSequence();
        encoder.encodeIA5String("testing");
        encoder.encodeIA5String("again");
        encoder.endSequence();

        encoder.encodeIA5String("test1@rsa.com");

        // Flush will end the unfinished set and sequence
        encoder.flush();

        byte[] expected = new byte[] {48, 84, 22, 11, 116, 101, 115, 116, 32, 115, 116, 114, 105, 110, 103, 4, 8, 1, 35, 69, 103, -119, -85, -51, -17,  49, 59, 4, 8, 1, 35, 69, 103, -119, -85, -51, -17, 48, 16, 22, 7, 116, 101, 115, 116, 105, 110, 103, 22, 5, 97, 103, 97, 105, 110, 22, 14, 116, 104, 105, 115, 32, 105, 115, 32, 97, 32, 116, 101, 115, 116, 22, 13, 116, 101, 115, 116, 49, 64, 114, 115, 97, 46, 99, 111, 109};
        assertArrayEquals(expected, target.toArray());
    }
}
