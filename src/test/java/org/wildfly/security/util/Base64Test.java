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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.nio.charset.StandardCharsets;

import org.junit.Assert;
import org.junit.Test;

/**
 * Tests of encoding/decoding Base64 B (standard alphabet)
 * implemented in org.wildfly.security.util.Base64
 *
 * @author <a href="mailto:jkalina@redhat.com">Jan Kalina</a>
 */
public class Base64Test {

    /*
     * Standard Base64 alphabet encoding
     * (Expected values by http://www.freeformatter.com/base64-encoder.html)
     */

    @Test
    public void testEncodeBlank() {
        assertEquals("", ByteIterator.EMPTY.base64Encode().drainToString());
    }

    @Test
    public void testEncodeWithoutPadding() {
        assertEquals("YWJj", CodePointIterator.ofString("abc").asLatin1().base64Encode().drainToString());
    }

    @Test
    public void testEncodeWith1Padding() {
        assertEquals("YWI=", CodePointIterator.ofString("ab").asLatin1().base64Encode().drainToString());
    }

    @Test
    public void testEncodeWith2Padding() {
        assertEquals("YWJjZA==", CodePointIterator.ofString("abcd").asLatin1().base64Encode().drainToString());
    }

    @Test
    public void testEncodeWithTurnedOffPadding() {
        assertEquals("YWJjZA", CodePointIterator.ofString("abcd").asLatin1().base64Encode(Alphabet.STANDARD, false).drainToString());
    }

    @Test
    public void testEncodeBinary() {
        assertEquals("AAEjRWeJq83v", ByteIterator.ofBytes((byte)0x00,(byte)0x01,(byte)0x23,(byte)0x45,(byte)0x67,(byte)0x89,(byte)0xAB,(byte)0xCD,(byte)0xEF).base64Encode().drainToString());
    }

    @Test
    public void testEncodeRfc1() {
        assertEquals("Zg==", CodePointIterator.ofString("f").asLatin1().base64Encode().drainToString());
    }

    @Test
    public void testEncodeRfc2() {
        assertEquals("Zm8=", CodePointIterator.ofString("fo").asLatin1().base64Encode().drainToString());
    }

    @Test
    public void testEncodeRfc3() {
        assertEquals("Zm9v", CodePointIterator.ofString("foo").asLatin1().base64Encode().drainToString());
    }

    @Test
    public void testEncodeRfc4() {
        assertEquals("Zm9vYg==", CodePointIterator.ofString("foob").asLatin1().base64Encode().drainToString());
    }

    @Test
    public void testEncodeRfc5() {
        assertEquals("Zm9vYmE=", CodePointIterator.ofString("fooba").asLatin1().base64Encode().drainToString());
    }

    @Test
    public void testEncodeRfc6() {
        assertEquals("Zm9vYmFy", CodePointIterator.ofString("foobar").asLatin1().base64Encode().drainToString());
    }

    @Test
    public void testEncodeAgainstPrecomputedValue() throws Exception {
        final byte[] input = "Testing input of base64 function".getBytes("UTF-8");
        final String output = CodePointIterator.ofString("Testing input of base64 function").asLatin1().base64Encode().drainToString();

        Assert.assertEquals("VGVzdGluZyBpbnB1dCBvZiBiYXNlNjQgZnVuY3Rpb24=", output);
        Assert.assertArrayEquals(input, CodePointIterator.ofString(output).base64Decode().drain());
    }


    /*
     * Standard Base64 alphabet decoding
     * (Expected values by http://www.freeformatter.com/base64-encoder.html)
     */

    @Test
    public void testDecodeBlank() throws Exception {
        Assert.assertArrayEquals(new byte[]{}, CodePointIterator.EMPTY.base64Decode(Alphabet.STANDARD, false).drain());
    }

    @Test
    public void testDecodeWithoutPadding() throws Exception {
        assertEquals("abc", CodePointIterator.ofString("YWJj").base64Decode(Alphabet.STANDARD, false).drainToUtf8String());
    }

    @Test
    public void testDecodeWith1Padding() throws Exception {
        assertEquals("ab", CodePointIterator.ofString("YWI=").base64Decode(Alphabet.STANDARD, false).drainToUtf8String());
    }

    @Test
    public void testDecodeWith2Padding() throws Exception {
        assertEquals("abcd", CodePointIterator.ofString("YWJjZA==").base64Decode(Alphabet.STANDARD, false).drainToUtf8String());
    }

    @Test
    public void testDecodeBinary() throws Exception {
        byte[] out = CodePointIterator.ofString("AAEjRWeJq83v").base64Decode(Alphabet.STANDARD, false).drain();
        Assert.assertArrayEquals(new byte[]{(byte)0x00,(byte)0x01,(byte)0x23,(byte)0x45,(byte)0x67,(byte)0x89,(byte)0xAB,(byte)0xCD,(byte)0xEF}, out);
    }

    @Test
    public void testDecodeRfc1() throws Exception {
        assertEquals("f", CodePointIterator.ofString("Zg==").base64Decode(Alphabet.STANDARD, false).drainToUtf8String());
    }

    @Test
    public void testDecodeRfc2() throws Exception {
        assertEquals("fo", CodePointIterator.ofString("Zm8=").base64Decode(Alphabet.STANDARD, false).drainToUtf8String());
    }

    @Test
    public void testDecodeRfc3() throws Exception {
        assertEquals("foo", CodePointIterator.ofString("Zm9v").base64Decode(Alphabet.STANDARD, false).drainToUtf8String());
    }

    @Test
    public void testDecodeRfc4() throws Exception {
        assertEquals("foob", CodePointIterator.ofString("Zm9vYg==").base64Decode(Alphabet.STANDARD, false).drainToUtf8String());
    }

    @Test
    public void testDecodeRfc5() throws Exception {
        assertEquals("fooba", CodePointIterator.ofString("Zm9vYmE=").base64Decode(Alphabet.STANDARD, false).drainToUtf8String());
    }

    @Test
    public void testDecodeRfc6() throws Exception {
        assertEquals("foobar", CodePointIterator.ofString("Zm9vYmFy").base64Decode(Alphabet.STANDARD, false).drainToUtf8String());
    }


    /*
     * Bcrypt Base64 alphabet encoding
     * (Expected values by php-litesec library - https://github.com/Jacques1/php-litesec/blob/master/src/password_hash.php)
     */

    @Test
    public void testBcryptEncodeF() {
        assertEquals("Xe", CodePointIterator.ofString("f").asLatin1().base64Encode(Alphabet.BCRYPT, false).drainToString());
    }

    @Test
    public void testBcryptEncodeFoobar() {
        assertEquals("Xk7tWkDw", CodePointIterator.ofString("foobar").asLatin1().base64Encode(Alphabet.BCRYPT, false).drainToString());
    }

    @Test
    public void testBcryptEncodeUnicode() {
        assertEquals(".DRCm8EGrM85lM89tu", ByteIterator.ofBytes("\u0000\u0054\u0123\u1234\uFEDC\uFFFF".getBytes(StandardCharsets.UTF_8)).base64Encode(Alphabet.BCRYPT, false).drainToString());
    }


    /*
     * Bcrypt Base64 alphabet decoding
     * (Expected values by php-litesec library - https://github.com/Jacques1/php-litesec/blob/master/src/password_hash.php)
     */

    @Test
    public void testBcryptDecodeF() throws Exception {
        assertEquals("f", CodePointIterator.ofString("Xe").base64Decode(Alphabet.BCRYPT, false).drainToUtf8String());
    }

    @Test
    public void testBcryptDecodeFoobar() throws Exception {
        assertEquals("foobar", CodePointIterator.ofString("Xk7tWkDw").base64Decode(Alphabet.BCRYPT, false).drainToUtf8String());
    }

    @Test
    public void testBcryptDecodeUnicode() throws Exception {
        String in = ".DRCm8EGrM85lM89tu";
        assertArrayEquals(new byte[]{(byte)0x00,(byte)0x54,(byte)0xC4,(byte)0xA3,(byte)0xE1,(byte)0x88,(byte)0xB4,(byte)0xEF,(byte)0xBB,(byte)0x9C,(byte)0xEF,(byte)0xBF,(byte)0xBF}, CodePointIterator.ofString(in).base64Decode(Alphabet.BCRYPT, false).drain());
    }


    /*
     * ModCrypt Base64 alphabet encoding
     * (Expected values by https://github.com/magthe/sandi/blob/master/test-src/Codec/Binary/XxTest.hs)
     */

    @Test
    public void testModCryptEncodeF() {
        assertEquals("NU", ByteIterator.ofBytes("f".getBytes(StandardCharsets.UTF_8)).base64Encode(Alphabet.MOD_CRYPT, false).drainToString());
    }

    @Test
    public void testModCryptEncodeFo() {
        assertEquals("Naw", ByteIterator.ofBytes("fo".getBytes(StandardCharsets.UTF_8)).base64Encode(Alphabet.MOD_CRYPT, false).drainToString());
    }

    @Test
    public void testModCryptEncodeFoo() {
        assertEquals("Naxj", ByteIterator.ofBytes("foo".getBytes(StandardCharsets.UTF_8)).base64Encode(Alphabet.MOD_CRYPT, false).drainToString());
    }

    @Test
    public void testModCryptEncodeFoob() {
        assertEquals("NaxjMU", ByteIterator.ofBytes("foob".getBytes(StandardCharsets.UTF_8)).base64Encode(Alphabet.MOD_CRYPT, false).drainToString());
    }

    @Test
    public void testModCryptEncodeFooba() {
        assertEquals("NaxjMa2", ByteIterator.ofBytes("fooba".getBytes(StandardCharsets.UTF_8)).base64Encode(Alphabet.MOD_CRYPT, false).drainToString());
    }

    @Test
    public void testModCryptEncodeFoobar() {
        assertEquals("NaxjMa3m", ByteIterator.ofBytes("foobar".getBytes(StandardCharsets.UTF_8)).base64Encode(Alphabet.MOD_CRYPT, false).drainToString());
    }


    /*
     * ModCrypt Base64 alphabet decoding
     * (Expected values by https://github.com/magthe/sandi/blob/master/test-src/Codec/Binary/XxTest.hs)
     */

    @Test
    public void testModCryptDecodeF() throws Exception {
        assertEquals("f", CodePointIterator.ofString("NU").base64Decode(Alphabet.MOD_CRYPT, false).drainToUtf8String());
    }

    @Test
    public void testModCryptDecodeFo() throws Exception {
        assertEquals("fo", CodePointIterator.ofString("Naw").base64Decode(Alphabet.MOD_CRYPT, false).drainToUtf8String());
    }

    @Test
    public void testModCryptDecodeFoo() throws Exception {
        assertEquals("foo", CodePointIterator.ofString("Naxj").base64Decode(Alphabet.MOD_CRYPT, false).drainToUtf8String());
    }

    @Test
    public void testModCryptDecodeFoob() throws Exception {
        assertEquals("foob", CodePointIterator.ofString("NaxjMU").base64Decode(Alphabet.MOD_CRYPT, false).drainToUtf8String());
    }

    @Test
    public void testModCryptDecodeFooba() throws Exception {
        assertEquals("fooba", CodePointIterator.ofString("NaxjMa2").base64Decode(Alphabet.MOD_CRYPT, false).drainToUtf8String());
    }

    @Test
    public void testModCryptDecodeFoobar() throws Exception {
        assertEquals("foobar", CodePointIterator.ofString("NaxjMa3m").base64Decode(Alphabet.MOD_CRYPT, false).drainToUtf8String());
    }


    /*
     * ModCrypt LE Base64 alphabet encoding
     * (Expected values by https://github.com/olethanh/django-phpbb/blob/master/phpbb/password_unittest.py)
     */

    @Test
    public void testModCryptLeEncodeF() {
        assertEquals("a/", CodePointIterator.ofString("f").asLatin1().base64Encode(Alphabet.MOD_CRYPT_LE, false).drainToString());
    }

    @Test
    public void testModCryptLeEncodeFoobar() {
        assertEquals("axqPW3aQ", CodePointIterator.ofString("foobar").asLatin1().base64Encode(Alphabet.MOD_CRYPT_LE, false).drainToString());
    }


    /*
     * ModCrypt Base64 alphabet decoding
     * (Expected values by https://github.com/olethanh/django-phpbb/blob/master/phpbb/password_unittest.py)
     */

    @Test
    public void testModCryptLeDecodeF() throws Exception {
        assertEquals("f", CodePointIterator.ofChars("a/".toCharArray()).base64Decode(Alphabet.MOD_CRYPT_LE, false).drainToUtf8String());
    }

    @Test
    public void testModCryptLeDecodeFoobar() throws Exception {
        assertEquals("foobar", CodePointIterator.ofChars("axqPW3aQ".toCharArray()).base64Decode(Alphabet.MOD_CRYPT_LE, false).drainToUtf8String());
    }


    /*
     * Decoding of invalid input
     */

    @Test(expected=IllegalArgumentException.class)
    public void testInvalidInputDecodePadding1() throws Exception {
        CodePointIterator.ofString("=").base64Decode(Alphabet.STANDARD, false).drain();
    }

    @Test(expected=IllegalArgumentException.class)
    public void testInvalidInputDecodePadding2() throws Exception {
        CodePointIterator.ofString("==").base64Decode(Alphabet.STANDARD, false).drain();
    }

    @Test(expected=IllegalArgumentException.class)
    public void testInvalidInputDecodePadding3() throws Exception {
        CodePointIterator.ofString("===").base64Decode(Alphabet.STANDARD, false).drain();
    }

    @Test(expected=IllegalArgumentException.class)
    public void testInvalidInputDecodeNonAlphabeticChar() throws Exception {
        CodePointIterator.ofString("áááááááááááá").base64Decode(Alphabet.STANDARD, false).drain();
    }

    public void testInvalidInputDecodeTooMuchPadding() throws Exception {
        final CodePointIterator r = CodePointIterator.ofString("YWI==");
        r.base64Decode(Alphabet.STANDARD, false).drain();
        assertTrue(r.hasNext());
        assertEquals('=', r.next());
        assertFalse(r.hasNext());
    }


    /*
     * General Base64 tests
     */

    /**
     * Tests if encoding/decoding works properly.
     * (data length) % 3 == 0
     */
    @Test
    public void testEncodeDecodeToByteStringBuilderMod0() throws Exception {
        doEncodeDecodeTest(generateSequence(255));
    }

    /**
     * Tests if encoding/decoding works properly.
     * (data length) % 3 == 1
     */
    @Test
    public void testEncodeDecodeToByteStringBuilderMod1() throws Exception {
        doEncodeDecodeTest(generateSequence(256));
    }

    /**
     * Tests if encoding/decoding works properly.
     * (data length) % 3 == 2
     */
    @Test
    public void testEncodeDecodeToByteStringBuilderMod2() throws Exception {
        doEncodeDecodeTest(generateSequence(257));
    }

    private void doEncodeDecodeTest(byte[] inputData) throws Exception {
        byte[] outputData = ByteIterator.ofBytes(inputData).base64Encode().base64Decode().drain();
        assertArrayEquals("Encode-Decode test failed, results are not the same.", inputData, outputData);
    }

    private byte[] generateSequence(final int len) {
        byte[] data = new byte[len];
        for (int i = 0; i < len ; i++) {
            data[i] = (byte)i;
        }
        return data;
    }

}
