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
package org.wildfly.security.sasl.test;

import static org.junit.Assert.*;

import java.security.MessageDigest;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.junit.Assert;
import org.junit.Test;
import org.wildfly.common.iteration.ByteIterator;
import org.wildfly.security.util.ByteStringBuilder;

/**
 * Tests of org.wildfly.security.sasl.util.ByteStringBuilder
 *
 * @author <a href="mailto:jkalina@redhat.com">Jan Kalina</a>
 */
public class ByteStringBuilderTest {

    @Test
    public void testInit() throws Exception {
        ByteStringBuilder b = new ByteStringBuilder();
        assertEquals(0, b.length());
        Assert.assertArrayEquals(new byte[]{}, b.toArray());
        assertTrue(b.contentEquals(new byte[]{}));
        assertTrue(b.contentEquals(new byte[]{}, 0, 0));
    }

    @Test
    public void testAppendByte() throws Exception {
        ByteStringBuilder b = new ByteStringBuilder(new byte[]{0x00});
        assertEquals(1, b.length());
        Assert.assertArrayEquals(new byte[]{0x00}, b.toArray());
        b.append((byte) 0x01);
        assertEquals(2, b.length());
        Assert.assertArrayEquals(new byte[]{0x00, 0x01}, b.toArray());
        assertTrue(b.contentEquals(new byte[]{(byte) 0x00, (byte) 0x01}));
        assertTrue(b.contentEquals(new byte[]{(byte) 0x99, (byte) 0x00, (byte) 0x01, (byte) 0x99}, 1, 2));
    }

    @Test
    public void testAppendIntoBlank() throws Exception {
        ByteStringBuilder b = new ByteStringBuilder(new byte[]{});
        b.append((byte)0x61);
        Assert.assertArrayEquals(new byte[]{0x61}, b.toArray());
    }

    @Test
    public void testAppendBoolean() throws Exception {
        ByteStringBuilder b = new ByteStringBuilder(new byte[]{0x00});
        b.append(true);
        assertEquals(5, b.length());
        Assert.assertArrayEquals(new byte[]{0x00, 0x74, 0x72, 0x75, 0x65}, b.toArray());
        b.append(false);
        assertEquals(10, b.length());
        Assert.assertArrayEquals(new byte[]{0x00, 0x74, 0x72, 0x75, 0x65, 0x66, 0x61, 0x6C, 0x73, 0x65}, b.toArray());
    }

    @Test
    public void testAppendChar() throws Exception {
        ByteStringBuilder b = new ByteStringBuilder();
        b.append('a');
        assertEquals(1, b.length());
        Assert.assertArrayEquals(new byte[]{0x61}, b.toArray());
        b.append('b');
        assertEquals(2, b.length());
        Assert.assertArrayEquals(new byte[]{0x61, 0x62}, b.toArray());
    }

    @Test
    public void testAppendUtf8Raw() throws Exception {
        ByteStringBuilder b = new ByteStringBuilder(new byte[]{0x00});
        b.appendUtf8Raw(0x61);
        assertEquals(2, b.length());
        Assert.assertArrayEquals(new byte[]{(byte) 0x00, (byte) 0x61}, b.toArray());
        b.appendUtf8Raw(0x0438);
        assertEquals(4, b.length());
        Assert.assertArrayEquals(new byte[]{(byte) 0x00, (byte) 0x61, (byte) 0xD0, (byte) 0xB8}, b.toArray());
        b.appendUtf8Raw(0x4F60);
        assertEquals(7, b.length());
        Assert.assertArrayEquals(new byte[]{(byte) 0x00, (byte) 0x61, (byte) 0xD0, (byte) 0xB8, (byte) 0xE4, (byte) 0xBD, (byte) 0xA0}, b.toArray());
        b.appendUtf8Raw(0x1F0A1);
        assertEquals(11, b.length());
        Assert.assertArrayEquals(new byte[]{(byte) 0x00, (byte) 0x61, (byte) 0xD0, (byte) 0xB8, (byte) 0xE4, (byte) 0xBD, (byte) 0xA0, (byte) 0xF0, (byte) 0x9F, (byte) 0x82, (byte) 0xA1}, b.toArray());
        b.appendUtf8Raw(0x10FFFF);
        assertEquals(15, b.length());
        Assert.assertArrayEquals(new byte[]{(byte) 0x00, (byte) 0x61, (byte) 0xD0, (byte) 0xB8, (byte) 0xE4, (byte) 0xBD, (byte) 0xA0, (byte) 0xF0, (byte) 0x9F, (byte) 0x82, (byte) 0xA1, (byte) 0xF4, (byte) 0x8F, (byte) 0xBF, (byte) 0xBF}, b.toArray());
    }

    @Test
    public void testAppendUtf8RawLonelySurrogate() throws Exception {
        ByteStringBuilder b = new ByteStringBuilder(new byte[]{});
        b.appendUtf8Raw(0xD800);
        Assert.assertArrayEquals(new byte[]{(byte) 0xED, (byte)0xA0, (byte) 0x80}, b.toArray());
        b.appendUtf8Raw(0xD8FF);
        Assert.assertArrayEquals(new byte[]{(byte) 0xED, (byte)0xA0, (byte) 0x80, (byte) 0xED, (byte) 0xA3, (byte) 0xBF}, b.toArray());
    }

    @Test
    public void testAppendUtf8Char() throws Exception {
        ByteStringBuilder b = new ByteStringBuilder(new byte[]{0x00});
        b.append('a');
        assertEquals(2, b.length());
        Assert.assertArrayEquals(new byte[]{(byte) 0x00, (byte) 0x61}, b.toArray());
        b.append('и');
        assertEquals(4, b.length());
        Assert.assertArrayEquals(new byte[]{(byte) 0x00, (byte) 0x61, (byte) 0xD0, (byte) 0xB8}, b.toArray());
        b.append('你');
        assertEquals(7, b.length());
        Assert.assertArrayEquals(new byte[]{(byte) 0x00, (byte) 0x61, (byte) 0xD0, (byte) 0xB8, (byte) 0xE4, (byte) 0xBD, (byte) 0xA0}, b.toArray());
        b.append('\uD800');
        assertEquals(10, b.length());
        Assert.assertArrayEquals(new byte[]{(byte) 0x00, (byte) 0x61, (byte) 0xD0, (byte) 0xB8, (byte) 0xE4, (byte) 0xBD, (byte) 0xA0, (byte) 0xED, (byte) 0xA0, (byte) 0x80}, b.toArray());
    }

    @Test
    public void testAppendBytes() throws Exception {
        ByteStringBuilder b = new ByteStringBuilder();
        b.append((byte) 0x00);
        b.append(new byte[]{0x11, 0x22});
        assertEquals(3, b.length());
        Assert.assertArrayEquals(new byte[]{(byte) 0x00, (byte) 0x11, (byte) 0x22}, b.toArray());
    }

    @Test
    public void testAppendPartOfBytes() throws Exception {
        byte[] bytes3456 = new byte[]{0x33, 0x44, 0x55, 0x66};
        ByteStringBuilder b = new ByteStringBuilder(new byte[]{0x11, 0x22});
        b.append(bytes3456, 1, 2);
        assertEquals(4, b.length()); // inner
        Assert.assertArrayEquals(new byte[]{(byte) 0x11, (byte) 0x22, (byte) 0x44, (byte) 0x55}, b.toArray());
        b.append(bytes3456, 0, 0); // nothing
        assertEquals(4, b.length());
        Assert.assertArrayEquals(new byte[]{(byte) 0x11, (byte) 0x22, (byte) 0x44, (byte) 0x55}, b.toArray());
        b.append(bytes3456, 0, 1); // first
        assertEquals(5, b.length());
        Assert.assertArrayEquals(new byte[]{(byte) 0x11, (byte) 0x22, (byte) 0x44, (byte) 0x55, (byte) 0x33}, b.toArray());
        b.append(bytes3456, 3, 1); // last
        assertEquals(6, b.length());
        Assert.assertArrayEquals(new byte[]{(byte) 0x11, (byte) 0x22, (byte) 0x44, (byte) 0x55, (byte) 0x33, (byte) 0x66}, b.toArray());
    }

    @Test
    public void testAppendCharSequence() throws Exception {
        ByteStringBuilder b = new ByteStringBuilder(new byte[]{0x00});
        b.append((CharSequence) "ab");
        b.append((CharSequence) "c你");
        assertEquals(7, b.length());
        Assert.assertArrayEquals(new byte[]{(byte) 0x00, (byte) 0x61, (byte) 0x62, (byte) 0x63, (byte) 0xE4, (byte) 0xBD, (byte) 0xA0}, b.toArray());
    }

    @Test
    public void testAppendPartOfCharSequence() throws Exception {
        ByteStringBuilder b = new ByteStringBuilder(new byte[]{0x00});
        b.append((CharSequence) "abcd", 1, 2);
        assertEquals(3, b.length());
        Assert.assertArrayEquals(new byte[]{(byte) 0x00, (byte) 0x62, (byte) 0x63}, b.toArray());
    }

    @Test
    public void testAppendString() throws Exception {
        ByteStringBuilder b = new ByteStringBuilder(new byte[]{0x00});
        b.append("ab");
        assertEquals(3, b.length());
        Assert.assertArrayEquals(new byte[]{(byte) 0x00, (byte) 0x61, (byte) 0x62}, b.toArray());
        b.append("c你");
        assertEquals(7, b.length());
        Assert.assertArrayEquals(new byte[]{(byte) 0x00, (byte) 0x61, (byte) 0x62, (byte) 0x63, (byte) 0xE4, (byte) 0xBD, (byte) 0xA0}, b.toArray());
    }

    @Test
    public void testAppendPartOfString() throws Exception {
        ByteStringBuilder b = new ByteStringBuilder(new byte[]{0x68}); // "h"
        b.append("abcd", 1, 2); // append "bc"
        assertEquals(3, b.length());
        Assert.assertArrayEquals(new byte[]{(byte) 0x68, (byte) 0x62, (byte) 0x63}, b.toArray());
        b.append("abcd", 0, 1); // append "a"
        assertEquals(4, b.length());
        Assert.assertArrayEquals(new byte[]{(byte) 0x68, (byte) 0x62, (byte) 0x63, (byte) 0x61}, b.toArray());
    }

    @Test
    public void testAppendLatin1CharSequence() throws Exception {
        ByteStringBuilder b = new ByteStringBuilder(new byte[]{0x00});
        b.appendLatin1((CharSequence) "ab");
        b.appendLatin1((CharSequence) "cä");
        assertEquals(5, b.length());
        Assert.assertArrayEquals(new byte[]{(byte) 0x00, (byte) 0x61, (byte) 0x62, (byte) 0x63, (byte) 0xE4}, b.toArray());
    }

    @Test
    public void testAppendLatin1PartOfCharSequence() throws Exception {
        ByteStringBuilder b = new ByteStringBuilder(new byte[]{0x68});
        b.appendLatin1((CharSequence) "abcd", 1, 2);
        assertEquals(3, b.length());
        Assert.assertArrayEquals(new byte[]{(byte) 0x68, (byte) 0x62, (byte) 0x63}, b.toArray());
    }

    @Test
    public void testAppendLatin1String() throws Exception {
        ByteStringBuilder b = new ByteStringBuilder(new byte[]{0x00});
        b.appendLatin1("ab");
        assertEquals(3, b.length());
        Assert.assertArrayEquals(new byte[]{(byte) 0x00, (byte) 0x61, (byte) 0x62}, b.toArray());
        b.appendLatin1("cä");
        assertEquals(5, b.length());
        Assert.assertArrayEquals(new byte[]{(byte) 0x00, (byte) 0x61, (byte) 0x62, (byte) 0x63, (byte) 0xE4}, b.toArray());
    }

    @Test
    public void testAppendLatin1PartOfString() throws Exception {
        ByteStringBuilder b = new ByteStringBuilder(new byte[]{0x00});
        b.appendLatin1("abcd", 1, 2);
        assertEquals(3, b.length());
        Assert.assertArrayEquals(new byte[]{(byte) 0x00, (byte) 0x62, (byte) 0x63}, b.toArray());
        b.appendLatin1("abcd", 0, 1);
        assertEquals(4, b.length());
        Assert.assertArrayEquals(new byte[]{(byte) 0x00, (byte) 0x62, (byte) 0x63, (byte) 0x61}, b.toArray());
    }

    @Test
    public void testAppendBE() throws Exception {
        ByteStringBuilder b = new ByteStringBuilder(new byte[]{0x00});
        b.appendBE(0x12345678);
        assertEquals(5, b.length());
        Assert.assertArrayEquals(new byte[]{(byte) 0x00, (byte) 0x12, (byte) 0x34, (byte) 0x56, (byte) 0x78}, b.toArray());
        b.appendBE(0x0123456789ABCDEFL);
        assertEquals(13, b.length());
        Assert.assertArrayEquals(new byte[]{(byte) 0x00, (byte) 0x12, (byte) 0x34, (byte) 0x56, (byte) 0x78, (byte) 0x01, (byte) 0x23, (byte) 0x45, (byte) 0x67, (byte) 0x89, (byte) 0xAB, (byte) 0xCD, (byte) 0xEF}, b.toArray());
    }

    @Test
    public void testAppendNumber() throws Exception {
        ByteStringBuilder b = new ByteStringBuilder(new byte[]{0x00});
        b.appendNumber(12);
        assertEquals(3, b.length());
        Assert.assertArrayEquals(new byte[]{(byte) 0x00, (byte) 0x31, (byte) 0x32}, b.toArray());
        b.appendNumber((long) 34);
        Assert.assertArrayEquals(new byte[]{(byte) 0x00, (byte) 0x31, (byte) 0x32, (byte) 0x33, (byte) 0x34}, b.toArray());
    }

    @Test
    public void testAppendObject() throws Exception {
        ByteStringBuilder b = new ByteStringBuilder(new byte[]{0x00});
        b.appendObject(new Integer(12));
        assertEquals(3, b.length());
        Assert.assertArrayEquals(new byte[]{(byte) 0x00, (byte) 0x31, (byte) 0x32}, b.toArray());
        b.appendObject(new Integer(34));
        Assert.assertArrayEquals(new byte[]{(byte) 0x00, (byte) 0x31, (byte) 0x32, (byte) 0x33, (byte) 0x34}, b.toArray());
    }

    @Test
    public void testAppendByteStringBuilder() throws Exception {
        ByteStringBuilder b = new ByteStringBuilder(new byte[]{0x00, 0x01});
        ByteStringBuilder apended = new ByteStringBuilder(new byte[]{0x02, 0x03});
        b.append(apended);
        assertEquals(4, b.length());
        Assert.assertArrayEquals(new byte[]{(byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03}, b.toArray());
    }

    @Test
    public void testUpdateMac() throws Exception {
        ByteStringBuilder b = new ByteStringBuilder(new byte[]{0x12, 0x34, 0x56});
        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(new SecretKeySpec(new byte[]{(byte) 0x47, (byte) 0x67, (byte) 0xFC}, "HmacSHA256"));
        b.updateMac(mac);
        byte[] d = mac.doFinal();
        Assert.assertArrayEquals(new byte[]{(byte) 0x99, (byte) 0x83, (byte) 0xDF, (byte) 0x83, (byte) 0x66, (byte) 0xD9, (byte) 0x7C, (byte) 0xC9, (byte) 0x3E, (byte) 0x41, (byte) 0x9E, (byte) 0xAB, (byte) 0x62, (byte) 0x24, (byte) 0x7A, (byte) 0x75, (byte) 0x9B, (byte) 0x2D, (byte) 0x8E, (byte) 0xCB}, d);
    }

    @Test
    public void testUpdateDigest() throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        ByteStringBuilder b = new ByteStringBuilder();
        b.append("abc");
        b.updateDigest(md);
        byte[] d = md.digest();
        Assert.assertArrayEquals(new byte[]{(byte) 0x90, (byte) 0x01, (byte) 0x50, (byte) 0x98, (byte) 0x3C, (byte) 0xD2, (byte) 0x4F, (byte) 0xB0, (byte) 0xD6, (byte) 0x96, (byte) 0x3F, (byte) 0x7D, (byte) 0x28, (byte) 0xE1, (byte) 0x7F, (byte) 0x72}, d);
    }

    @Test
    public void testCapacity() throws Exception {
        ByteStringBuilder b = new ByteStringBuilder();
        assertTrue(b.capacity() >= 0);
        b.append("123456789012345678901234567890");
        assertTrue(b.capacity() >= 30);
    }

    private byte[] bytes(int... ints) {
        final byte[] bytes = new byte[ints.length];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) ints[i];
        }
        return bytes;
    }

    @Test
    public void testPacked() throws Exception {
        ByteStringBuilder b = new ByteStringBuilder();
        b.appendPackedUnsignedBE(0);
        Assert.assertArrayEquals(bytes(0), b.toArray());
        b.setLength(0);
        b.appendPackedUnsignedBE(0x12);
        Assert.assertArrayEquals(bytes(0x12), b.toArray());
        b.setLength(0);
        b.appendPackedUnsignedBE(0x123);
        Assert.assertArrayEquals(bytes(0x82, 0x23), b.toArray());
        b.setLength(0);
        b.appendPackedUnsignedBE(0x1234);
        Assert.assertArrayEquals(bytes(0xA4, 0x34), b.toArray());
        b.setLength(0);
        b.appendPackedUnsignedBE(0x12345);
        Assert.assertArrayEquals(bytes(0x84, 0xC6, 0x45), b.toArray());
        b.setLength(0);
        b.appendPackedUnsignedBE(0x1234567);
        Assert.assertArrayEquals(bytes(0x89, 0x8d, 0x8a, 0x67), b.toArray());
    }

    @Test
    public void testPackedInOut() throws Exception {
        ByteStringBuilder b = new ByteStringBuilder();
        b.appendPackedUnsignedBE(0);
        Assert.assertEquals(0, ByteIterator.ofBytes(b.toArray()).getPackedBE32());
        b.setLength(0);
        b.appendPackedUnsignedBE(0x12);
        Assert.assertEquals(0x12, ByteIterator.ofBytes(b.toArray()).getPackedBE32());
        b.setLength(0);
        b.appendPackedUnsignedBE(0x123);
        Assert.assertEquals(0x123, ByteIterator.ofBytes(b.toArray()).getPackedBE32());
        b.setLength(0);
        b.appendPackedUnsignedBE(0x1234);
        Assert.assertEquals(0x1234, ByteIterator.ofBytes(b.toArray()).getPackedBE32());
        b.setLength(0);
        b.appendPackedUnsignedBE(0x12345);
        Assert.assertEquals(0x12345, ByteIterator.ofBytes(b.toArray()).getPackedBE32());
        b.setLength(0);
        b.appendPackedUnsignedBE(0x1234567);
        Assert.assertEquals(0x1234567, ByteIterator.ofBytes(b.toArray()).getPackedBE32());
    }
}
