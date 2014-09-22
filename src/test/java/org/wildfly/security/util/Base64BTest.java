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

import static org.junit.Assert.*;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;

/**
 * Tests of encoding/decoding Base64 B (standard alphabet)
 * implemented in org.wildfly.security.util.Base64
 *
 * Reference output by: http://www.freeformatter.com/base64-encoder.html
 *
 * TODO Tests of other implemented variants of Base64 (A/ACryptLE/B/BCrypt)
 *
 * @author <a href="mailto:jkalina@redhat.com">Jan Kalina</a>
 */
public class Base64BTest {

    private static final char[] customAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".toCharArray();
    private static final int[] decodeCustomAlphabet = Base64.getDecodeAlphabet(customAlphabet, true);

    /* Base64 B Encoding */

    @Test
    public void testEncodeBlank() {
        ByteArrayInputStream in = new ByteArrayInputStream(new byte[]{});
        StringBuilder out = new StringBuilder();
        Base64.base64EncodeB(out, in, true);
        assertEquals("", out.toString());
    }

    @Test
    public void testEncodeWithoutPadding() {
        ByteArrayInputStream in = new ByteArrayInputStream("abc".getBytes(StandardCharsets.UTF_8));
        StringBuilder out = new StringBuilder();
        Base64.base64EncodeB(out, in, false);
        assertEquals("YWJj", out.toString());
    }

    @Test
    public void testEncodeWith1Padding() {
        ByteArrayInputStream in = new ByteArrayInputStream("ab".getBytes(StandardCharsets.UTF_8));
        StringBuilder out = new StringBuilder();
        Base64.base64EncodeB(out, in, true);
        assertEquals("YWI=", out.toString());
    }

    @Test
    public void testEncodeWith2Padding() {
        ByteArrayInputStream in = new ByteArrayInputStream("abcd".getBytes(StandardCharsets.UTF_8));
        StringBuilder out = new StringBuilder();
        Base64.base64EncodeB(out, in, true);
        assertEquals("YWJjZA==", out.toString());
    }

    @Test
    public void testEncodeBinary() {
        ByteArrayInputStream in = new ByteArrayInputStream(new byte[]{(byte)0x00,(byte)0x01,(byte)0x23,(byte)0x45,(byte)0x67,(byte)0x89,(byte)0xAB,(byte)0xCD,(byte)0xEF});
        StringBuilder out = new StringBuilder();
        Base64.base64EncodeB(out, in, true);
        assertEquals("AAEjRWeJq83v", out.toString());
    }

    @Test
    public void testEncodeRfc1() {
        ByteArrayInputStream in = new ByteArrayInputStream("f".getBytes(StandardCharsets.UTF_8));
        StringBuilder out = new StringBuilder();
        Base64.base64EncodeB(out, in, true);
        assertEquals("Zg==", out.toString());
    }

    @Test
    public void testEncodeRfc2() {
        ByteArrayInputStream in = new ByteArrayInputStream("fo".getBytes(StandardCharsets.UTF_8));
        StringBuilder out = new StringBuilder();
        Base64.base64EncodeB(out, in, true);
        assertEquals("Zm8=", out.toString());
    }

    @Test
    public void testEncodeRfc3() {
        ByteArrayInputStream in = new ByteArrayInputStream("foo".getBytes(StandardCharsets.UTF_8));
        StringBuilder out = new StringBuilder();
        Base64.base64EncodeB(out, in, true);
        assertEquals("Zm9v", out.toString());
    }

    @Test
    public void testEncodeRfc4() {
        ByteArrayInputStream in = new ByteArrayInputStream("foob".getBytes(StandardCharsets.UTF_8));
        StringBuilder out = new StringBuilder();
        Base64.base64EncodeB(out, in, true);
        assertEquals("Zm9vYg==", out.toString());
    }

    @Test
    public void testEncodeRfc5() {
        ByteArrayInputStream in = new ByteArrayInputStream("fooba".getBytes(StandardCharsets.UTF_8));
        StringBuilder out = new StringBuilder();
        Base64.base64EncodeB(out, in, true);
        assertEquals("Zm9vYmE=", out.toString());
    }

    @Test
    public void testEncodeRfc6() {
        ByteArrayInputStream in = new ByteArrayInputStream("foobar".getBytes(StandardCharsets.UTF_8));
        StringBuilder out = new StringBuilder();
        Base64.base64EncodeB(out, in, true);
        assertEquals("Zm9vYmFy", out.toString());
    }

    /* Base64 B Decoding */

    @Test
    public void testDecodeBlank() throws Exception {
        char[] in = new char[]{};
        byte[] out = new byte[in.length * 3 / 4];
        CharacterArrayReader r = new CharacterArrayReader(in);
        Base64.base64DecodeB(r, out);
        r.close();
        Assert.assertArrayEquals(new byte[]{}, out);
        Assert.assertArrayEquals(new byte[]{}, Base64.base64DecodeB(in, 0));
    }

    @Test
    public void testDecodeWithoutPadding() throws Exception {
        char[] in = "YWJj".toCharArray();
        byte[] out = Base64.base64DecodeB(in, 0);
        assertEquals("abc", new String(out));
    }

    @Test
    public void testDecodeWith1Padding() throws Exception {
        char[] in = "YWI=".toCharArray();
        byte[] out = Base64.base64DecodeB(in, 0);
        assertEquals("ab", new String(out));
    }

    @Test
    public void testDecodeWith2Padding() throws Exception {
        char[] in = "YWJjZA==".toCharArray();
        byte[] out = Base64.base64DecodeB(in, 0);
        assertEquals("abcd", new String(out));
    }

    @Test
    public void testDecodeBinary() throws Exception {
        char[] in = "AAEjRWeJq83v".toCharArray();
        byte[] out = Base64.base64DecodeB(in, 0);
        Assert.assertArrayEquals(new byte[]{(byte)0x00,(byte)0x01,(byte)0x23,(byte)0x45,(byte)0x67,(byte)0x89,(byte)0xAB,(byte)0xCD,(byte)0xEF}, out);
    }

    @Test
    public void testDecodeRfc1() throws Exception {
        char[] in = "Zg==".toCharArray();
        byte[] out = Base64.base64DecodeB(in, 0);
        assertEquals("f", new String(out));
    }

    @Test
    public void testDecodeRfc2() throws Exception {
        char[] in = "Zm8=".toCharArray();
        byte[] out = Base64.base64DecodeB(in, 0);
        assertEquals("fo", new String(out));
    }

    @Test
    public void testDecodeRfc3() throws Exception {
        char[] in = "Zm9v".toCharArray();
        byte[] out = Base64.base64DecodeB(in, 0);
        assertEquals("foo", new String(out));
    }

    @Test
    public void testDecodeRfc4() throws Exception {
        char[] in = "Zm9vYg==".toCharArray();
        byte[] out = Base64.base64DecodeB(in, 0);
        assertEquals("foob", new String(out));
    }

    @Test
    public void testDecodeRfc5() throws Exception {
        char[] in = "Zm9vYmE=".toCharArray();
        byte[] out = Base64.base64DecodeB(in, 0);
        assertEquals("fooba", new String(out));
    }

    @Test
    public void testDecodeRfc6() throws Exception {
        char[] in = "Zm9vYmFy".toCharArray();
        byte[] out = Base64.base64DecodeB(in, 0);
        assertEquals("foobar", new String(out));
    }

    /* Custom Base64 alphabet encoding */
    // Expected values based on known values from org.apache.commons.codec.binary.Base64Test with a URL safe alphabet

    @Test
    public void testEncodeCustomBlank() {
        ByteArrayInputStream in = new ByteArrayInputStream(new byte[]{});
        StringBuilder out = new StringBuilder();
        Base64.base64Encode(out, in, customAlphabet, true);
        assertEquals("", out.toString());
    }

    @Test
    public void testEncodeCustomWithoutPadding() {
        ByteArrayInputStream in = new ByteArrayInputStream(new byte[]{ -1, 127, -113, -64, 28, -37, 71, 26, -116, -117, 90, -109, 6, 24, 63, -24 });
        StringBuilder out = new StringBuilder();
        Base64.base64Encode(out, in, customAlphabet, false);
        assertEquals("_3-PwBzbRxqMi1qTBhg_6A", out.toString());
    }

    @Test
    public void testEncodeCustomWithPadding() {
        ByteArrayInputStream in = new ByteArrayInputStream(new byte[]{ 100, -66, 21, 75, 111, -6, 64, 37, -115, 26, 1, 40, -114, 124, 49, -54 });
        StringBuilder out = new StringBuilder();
        Base64.base64Encode(out, in, customAlphabet, true);
        assertEquals("ZL4VS2_6QCWNGgEojnwxyg==", out.toString());
    }

    /* Custom Base64 alphabet decoding */
    // Expected values based on known values from org.apache.commons.codec.binary.Base64Test with a URL safe alphabet

    @Test
    public void testDecodeCustomBlank() throws Exception {
        char[] in = new char[]{};
        byte[] out = new byte[in.length * 3 / 4];
        CharacterArrayReader r = new CharacterArrayReader(in);
        Base64.base64Decode(r, out, decodeCustomAlphabet);
        r.close();
        Assert.assertArrayEquals(new byte[]{}, out);
        Assert.assertArrayEquals(new byte[]{}, Base64.base64Decode(in, 0, decodeCustomAlphabet));
    }

    @Test
    public void testDecodeCustomWithoutPadding() throws Exception {
        char[] in = "lO2NAxnkSTOZVg-2dATTcA".toCharArray();
        byte[] out = Base64.base64Decode(in, 0, decodeCustomAlphabet);
        assertArrayEquals(new byte[]{ -108, -19, -115, 3, 25, -28, 73, 51, -103, 86, 15, -74, 116, 4, -45, 112 }, out);
    }

    @Test
    public void testDecodeCustomWithPadding() throws Exception {
        char[] in = "K_fMJwH-Q5e0nr7tWsxwkA==".toCharArray();
        byte[] out = Base64.base64Decode(in, 0, decodeCustomAlphabet);
        assertArrayEquals(new byte[]{ 43, -9, -52, 39, 1, -2, 67, -105, -76, -98, -66, -19, 90, -52, 112, -112 }, out);
    }
}
