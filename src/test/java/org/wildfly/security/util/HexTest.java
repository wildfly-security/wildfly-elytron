/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2015 Red Hat, Inc., and individual contributors
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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

/**
 * Tests for Hex encoding and decoding. The expected results for these test cases have been
 * taken from the examples in <a href="https://tools.ietf.org/html/rfc4648">RFC 4648</a>.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public class HexTest {

    @Test
    public void testEncodeEmpty() {
        CodePointIterator ci = CodePointIterator.ofString("").asLatin1().hexEncode();
        String encoded = ci.drainToString();
        assertEquals("", encoded);
        verifyBackwardIterationOfEncodedCharacters(ci, encoded);
    }

    @Test
    public void testEncodeRfcExample1() {
        CodePointIterator ci = CodePointIterator.ofString("f").asLatin1().hexEncode();
        String encoded = ci.drainToString();
        assertEquals("66", encoded);
        verifyBackwardIterationOfEncodedCharacters(ci, encoded);
    }

    @Test
    public void testEncodeRfcExample2() {
        CodePointIterator ci = CodePointIterator.ofString("fo").asLatin1().hexEncode();
        String encoded = ci.drainToString();
        assertEquals("666f", encoded);
        verifyBackwardIterationOfEncodedCharacters(ci, encoded);
    }

    @Test
    public void testEncodeRfcExample3() {
        CodePointIterator ci = CodePointIterator.ofString("foo").asLatin1().hexEncode();
        String encoded = ci.drainToString();
        assertEquals("666f6f", encoded);
        verifyBackwardIterationOfEncodedCharacters(ci, encoded);
    }

    @Test
    public void testEncodeRfcExample4() {
        CodePointIterator ci = CodePointIterator.ofString("foob").asLatin1().hexEncode();
        String encoded = ci.drainToString();
        assertEquals("666f6f62", encoded);
        verifyBackwardIterationOfEncodedCharacters(ci, encoded);
    }

    @Test
    public void testEncodeRfcExample5() {
        CodePointIterator ci = CodePointIterator.ofString("fooba").asLatin1().hexEncode();
        String encoded = ci.drainToString();
        assertEquals("666f6f6261", encoded);
        verifyBackwardIterationOfEncodedCharacters(ci, encoded);
    }

    @Test
    public void testEncodeRfcExample6() {
        CodePointIterator ci = CodePointIterator.ofString("foobar").asLatin1().hexEncode();
        String encoded = ci.drainToString();
        assertEquals("666f6f626172", encoded);
        verifyBackwardIterationOfEncodedCharacters(ci, encoded);
    }

    @Test
    public void testEncodeUpperCase() {
        CodePointIterator ci = ByteIterator.ofBytes(new byte[]{(byte) 0x1d, (byte) 0x34, (byte) 0xaf, (byte) 0xbc, (byte) 0x9e, (byte) 0x89}).hexEncode(true);
        String encoded = ci.drainToString();
        assertEquals("1D34AFBC9E89", encoded);
        verifyBackwardIterationOfEncodedCharacters(ci, encoded);
    }

    @Test
    public void testEncodeWithFormatting() {
        assertEquals("66:6F:6F:62:61:72", CodePointIterator.ofString("foobar").asLatin1().hexEncode(true).drainToString(':', 2));
        assertEquals("0x66 0x6F 0x6F 0x62 0x61 0x72", CodePointIterator.ofString("foobar").asLatin1().hexEncode(true).drainToString("0x", ' ', 2));
        assertEquals("666F6F6261\n72666F6F62\n6172666F6F\n626172",
                CodePointIterator.ofString("foobarfoobarfoobar").asLatin1().hexEncode(true).drainToString('\n', 10));
    }

    private void verifyBackwardIterationOfEncodedCharacters(CodePointIterator ci, String encoded) {
        int encodedSize = encoded.length();
        for (int i = encodedSize - 1; i >= 0; i--) {
            assertTrue(ci.hasPrev());
            assertEquals(encoded.charAt(i), ci.prev());
        }
    }

    @Test
    public void testDecodeEmpty() throws Exception {
        ByteIterator bi = CodePointIterator.ofString("").hexDecode();
        String decoded = bi.asUtf8String().drainToString();
        assertEquals("", decoded);
        verifyBackwardIterationOfDecodedBytes(bi, decoded);
    }

    @Test
    public void testDecodeRfcExample1() throws Exception {
        ByteIterator bi = CodePointIterator.ofString("66").hexDecode();
        String decoded = bi.asUtf8String().drainToString();
        assertEquals("f", decoded);
        verifyBackwardIterationOfDecodedBytes(bi, decoded);
    }

    @Test
    public void testDecodeRfcExample2() throws Exception {
        ByteIterator bi = CodePointIterator.ofString("666f").hexDecode();
        String decoded = bi.asUtf8String().drainToString();
        assertEquals("fo", decoded);
        verifyBackwardIterationOfDecodedBytes(bi, decoded);
    }

    @Test
    public void testDecodeRfcExample3() throws Exception {
        ByteIterator bi = CodePointIterator.ofString("666f6f").hexDecode();
        String decoded = bi.asUtf8String().drainToString();
        assertEquals("foo", decoded);
        verifyBackwardIterationOfDecodedBytes(bi, decoded);
    }

    @Test
    public void testDecodeRfcExample4() throws Exception {
        ByteIterator bi = CodePointIterator.ofString("666f6f62").hexDecode();
        String decoded = bi.asUtf8String().drainToString();
        assertEquals("foob", decoded);
        verifyBackwardIterationOfDecodedBytes(bi, decoded);
    }

    @Test
    public void testDecodeRfcExample5() throws Exception {
        ByteIterator bi = CodePointIterator.ofString("666f6f6261").hexDecode();
        String decoded = bi.asUtf8String().drainToString();
        assertEquals("fooba", decoded);
        verifyBackwardIterationOfDecodedBytes(bi, decoded);
    }

    @Test
    public void testDecodeRfcExample6() throws Exception {
        ByteIterator bi = CodePointIterator.ofString("666f6f626172").hexDecode();
        String decoded = bi.asUtf8String().drainToString();
        assertEquals("foobar", decoded);
        verifyBackwardIterationOfDecodedBytes(bi, decoded);
    }

    @Test
    public void testDecodeUpperCase() throws Exception {
        ByteIterator bi = CodePointIterator.ofString("1D34AFBC9E89").hexDecode();
        byte[] decoded = bi.drain();
        assertArrayEquals(new byte[]{(byte) 0x1d, (byte) 0x34, (byte) 0xaf, (byte) 0xbc, (byte) 0x9e, (byte) 0x89}, decoded);
        verifyBackwardIterationOfDecodedBytes(bi, decoded);
    }

    @Test(expected=DecodeException.class)
    public void testDecodeInvalidCharacter() throws Exception {
        CodePointIterator.ofString("6h666f6f626172g").hexDecode().drain();
    }

    @Test(expected=DecodeException.class)
    public void testDecodeInvalidLength() throws Exception {
        CodePointIterator.ofChars(new char[]{'1', 'F', 'A'}).hexDecode().drain();
    }

    private void verifyBackwardIterationOfDecodedBytes(ByteIterator bi, String decoded) {
        int decodedSize = decoded.length();
        for (int i = decodedSize - 1; i >= 0; i--) {
            assertTrue(bi.hasPrev());
            assertEquals(decoded.charAt(i), bi.prev());
        }
    }

    private void verifyBackwardIterationOfDecodedBytes(ByteIterator bi, byte[] decoded) {
        int decodedSize = decoded.length;
        for (int i = decodedSize - 1; i >= 0; i--) {
            assertTrue(bi.hasPrev());
            assertEquals(decoded[i], (byte) bi.prev());
        }
    }
}
