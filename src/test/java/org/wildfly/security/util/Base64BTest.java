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

    /* Base64 B Encoding */

    @Test
    public void testEncodelank() throws Exception {
        ByteArrayIterator in = new ByteArrayIterator(new byte[]{});
        StringBuilder out = new StringBuilder();
        Base64.base64EncodeB(out, in);
        assertEquals("", out.toString());
    }

    @Test
    public void testEncodeWithoutPadding() throws Exception {
        ByteArrayIterator in = new ByteArrayIterator("abc".getBytes(StandardCharsets.UTF_8));
        StringBuilder out = new StringBuilder();
        Base64.base64EncodeB(out, in);
        assertEquals("YWJj", out.toString());
    }

    @Test
    @Ignore
    public void testEncodeWith1Padding() throws Exception {
        ByteArrayIterator in = new ByteArrayIterator("ab".getBytes(StandardCharsets.UTF_8));
        StringBuilder out = new StringBuilder();
        Base64.base64EncodeB(out, in);
        assertEquals("YWI=", out.toString());
    }

    @Test
    @Ignore
    public void testEncodeWith2Padding() throws Exception {
        ByteArrayIterator in = new ByteArrayIterator("abcd".getBytes(StandardCharsets.UTF_8));
        StringBuilder out = new StringBuilder();
        Base64.base64EncodeB(out, in);
        assertEquals("YWJjZA==", out.toString());
    }

    @Test
    public void testEncodeBinary() throws Exception {
        ByteArrayIterator in = new ByteArrayIterator(new byte[]{(byte)0x00,(byte)0x01,(byte)0x23,(byte)0x45,(byte)0x67,(byte)0x89,(byte)0xAB,(byte)0xCD,(byte)0xEF});
        StringBuilder out = new StringBuilder();
        Base64.base64EncodeB(out, in);
        assertEquals("AAEjRWeJq83v", out.toString());
    }

    @Test
    @Ignore
    public void testEncodeRfc1() throws Exception {
        ByteArrayIterator in = new ByteArrayIterator("f".getBytes(StandardCharsets.UTF_8));
        StringBuilder out = new StringBuilder();
        Base64.base64EncodeB(out, in);
        assertEquals("Zg==", out.toString());
    }

    @Test
    @Ignore
    public void testEncodeRfc2() throws Exception {
        ByteArrayIterator in = new ByteArrayIterator("fo".getBytes(StandardCharsets.UTF_8));
        StringBuilder out = new StringBuilder();
        Base64.base64EncodeB(out, in);
        assertEquals("Zm8=", out.toString());
    }

    @Test
    public void testEncodeRfc3() throws Exception {
        ByteArrayIterator in = new ByteArrayIterator("foo".getBytes(StandardCharsets.UTF_8));
        StringBuilder out = new StringBuilder();
        Base64.base64EncodeB(out, in);
        assertEquals("Zm9v", out.toString());
    }

    @Test
    @Ignore
    public void testEncodeRfc4() throws Exception {
        ByteArrayIterator in = new ByteArrayIterator("foob".getBytes(StandardCharsets.UTF_8));
        StringBuilder out = new StringBuilder();
        Base64.base64EncodeB(out, in);
        assertEquals("Zm9vYg==", out.toString());
    }

    @Test
    @Ignore
    public void testEncodeRfc5() throws Exception {
        ByteArrayIterator in = new ByteArrayIterator("fooba".getBytes(StandardCharsets.UTF_8));
        StringBuilder out = new StringBuilder();
        Base64.base64EncodeB(out, in);
        assertEquals("Zm9vYmE=", out.toString());
    }

    @Test
    public void testEncodeRfc6() throws Exception {
        ByteArrayIterator in = new ByteArrayIterator("foobar".getBytes(StandardCharsets.UTF_8));
        StringBuilder out = new StringBuilder();
        Base64.base64EncodeB(out, in);
        assertEquals("Zm9vYmFy", out.toString());
    }

    /* Base64 B Decoding */

    @Test
    public void testDecodeBlank() throws Exception {
        char[] in = new char[]{};
        byte[] out = new byte[in.length * 3 / 4];
        Base64.base64DecodeB(new CharacterArrayIterator(in), out);
        Assert.assertArrayEquals(new byte[]{}, out);
    }

    @Test
    public void testDecodeWithoutPadding() throws Exception {
        char[] in = "YWJj".toCharArray();
        byte[] out = new byte[in.length * 3 / 4];
        Base64.base64DecodeB(new CharacterArrayIterator(in), out);
        assertEquals("abc", new String(out));
    }

    @Test
    @Ignore
    public void testDecodeWith1Padding() throws Exception {
        char[] in = "YWI=".toCharArray();
        byte[] out = new byte[in.length * 3 / 4];
        Base64.base64DecodeB(new CharacterArrayIterator(in), out);
        assertEquals("ab", new String(out));
    }

    @Test
    @Ignore
    public void testDecodeWith2Padding() throws Exception {
        char[] in = "YWJjZA==".toCharArray();
        byte[] out = new byte[in.length * 3 / 4];
        Base64.base64DecodeB(new CharacterArrayIterator(in), out);
        assertEquals("abcd", new String(out));
    }

    @Test
    public void testDecodeBinary() throws Exception {
        char[] in = "AAEjRWeJq83v".toCharArray();
        byte[] out = new byte[in.length * 3 / 4];
        Base64.base64DecodeB(new CharacterArrayIterator(in), out);
        Assert.assertArrayEquals(new byte[]{(byte)0x00,(byte)0x01,(byte)0x23,(byte)0x45,(byte)0x67,(byte)0x89,(byte)0xAB,(byte)0xCD,(byte)0xEF}, out);
    }

    @Test
    @Ignore
    public void testDecodeRfc1() throws Exception {
        char[] in = "Zg==".toCharArray();
        byte[] out = new byte[in.length * 3 / 4];
        Base64.base64DecodeB(new CharacterArrayIterator(in), out);
        assertEquals("f", new String(out));
    }

    @Test
    @Ignore
    public void testDecodeRfc2() throws Exception {
        char[] in = "Zm8=".toCharArray();
        byte[] out = new byte[in.length * 3 / 4];
        Base64.base64DecodeB(new CharacterArrayIterator(in), out);
        assertEquals("fo", new String(out));
    }

    @Test
    public void testDecodeRfc3() throws Exception {
        char[] in = "Zm9v".toCharArray();
        byte[] out = new byte[in.length * 3 / 4];
        Base64.base64DecodeB(new CharacterArrayIterator(in), out);
        assertEquals("foo", new String(out));
    }

    @Test
    @Ignore
    public void testDecodeRfc4() throws Exception {
        char[] in = "Zm9vYg==".toCharArray();
        byte[] out = new byte[in.length * 3 / 4];
        Base64.base64DecodeB(new CharacterArrayIterator(in), out);
        assertEquals("foob", new String(out));
    }

    @Test
    @Ignore
    public void testDecodeRfc5() throws Exception {
        char[] in = "Zm9vYmE=".toCharArray();
        byte[] out = new byte[in.length * 3 / 4];
        Base64.base64DecodeB(new CharacterArrayIterator(in), out);
        assertEquals("fooba", new String(out));
    }

    @Test
    public void testDecodeRfc6() throws Exception {
        char[] in = "Zm9vYmFy".toCharArray();
        byte[] out = new byte[in.length * 3 / 4];
        Base64.base64DecodeB(new CharacterArrayIterator(in), out);
        assertEquals("foobar", new String(out));
    }

}
