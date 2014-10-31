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
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

import org.junit.Assert;
import org.junit.Test;
import org.wildfly.security.sasl.util.ByteStringBuilder;

/**
 * Tests of encoding/decoding Base64 B (standard alphabet)
 * implemented in org.wildfly.security.util.Base64
 *
 * @author <a href="mailto:jkalina@redhat.com">Jan Kalina</a>
 */
public class Base64Test {

    private static final char[] customAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".toCharArray();
    private static final int[] decodeCustomAlphabet = Base64.getDecodeAlphabet(customAlphabet, true);


    /*
     * Standard Base64 alphabet encoding
     * (Expected values by http://www.freeformatter.com/base64-encoder.html)
     */

    @Test
    public void testEncodeBlank() {
        ByteArrayInputStream in = new ByteArrayInputStream(new byte[]{});
        StringBuilder out = new StringBuilder();
        Base64.base64EncodeStandard(out, in, true);
        assertEquals("", out.toString());
    }

    @Test
    public void testEncodeWithoutPadding() {
        ByteArrayInputStream in = new ByteArrayInputStream("abc".getBytes(StandardCharsets.UTF_8));
        StringBuilder out = new StringBuilder();
        Base64.base64EncodeStandard(out, in, true);
        assertEquals("YWJj", out.toString());
    }

    @Test
    public void testEncodeWith1Padding() {
        ByteArrayInputStream in = new ByteArrayInputStream("ab".getBytes(StandardCharsets.UTF_8));
        StringBuilder out = new StringBuilder();
        Base64.base64EncodeStandard(out, in, true);
        assertEquals("YWI=", out.toString());
    }

    @Test
    public void testEncodeWith2Padding() {
        ByteArrayInputStream in = new ByteArrayInputStream("abcd".getBytes(StandardCharsets.UTF_8));
        StringBuilder out = new StringBuilder();
        Base64.base64EncodeStandard(out, in, true);
        assertEquals("YWJjZA==", out.toString());
    }

    @Test
    public void testEncodeWithTurnedOffPadding() {
        ByteArrayInputStream in = new ByteArrayInputStream("abcd".getBytes(StandardCharsets.UTF_8));
        StringBuilder out = new StringBuilder();
        Base64.base64EncodeStandard(out, in, false);
        assertEquals("YWJjZA", out.toString());
    }

    @Test
    public void testEncodeBinary() {
        ByteArrayInputStream in = new ByteArrayInputStream(new byte[]{(byte)0x00,(byte)0x01,(byte)0x23,(byte)0x45,(byte)0x67,(byte)0x89,(byte)0xAB,(byte)0xCD,(byte)0xEF});
        StringBuilder out = new StringBuilder();
        Base64.base64EncodeStandard(out, in, true);
        assertEquals("AAEjRWeJq83v", out.toString());
    }

    @Test
    public void testEncodeRfc1() {
        ByteArrayInputStream in = new ByteArrayInputStream("f".getBytes(StandardCharsets.UTF_8));
        StringBuilder out = new StringBuilder();
        Base64.base64EncodeStandard(out, in, true);
        assertEquals("Zg==", out.toString());
    }

    @Test
    public void testEncodeRfc2() {
        ByteArrayInputStream in = new ByteArrayInputStream("fo".getBytes(StandardCharsets.UTF_8));
        StringBuilder out = new StringBuilder();
        Base64.base64EncodeStandard(out, in, true);
        assertEquals("Zm8=", out.toString());
    }

    @Test
    public void testEncodeRfc3() {
        ByteArrayInputStream in = new ByteArrayInputStream("foo".getBytes(StandardCharsets.UTF_8));
        StringBuilder out = new StringBuilder();
        Base64.base64EncodeStandard(out, in, true);
        assertEquals("Zm9v", out.toString());
    }

    @Test
    public void testEncodeRfc4() {
        ByteArrayInputStream in = new ByteArrayInputStream("foob".getBytes(StandardCharsets.UTF_8));
        StringBuilder out = new StringBuilder();
        Base64.base64EncodeStandard(out, in, true);
        assertEquals("Zm9vYg==", out.toString());
    }

    @Test
    public void testEncodeRfc5() {
        ByteArrayInputStream in = new ByteArrayInputStream("fooba".getBytes(StandardCharsets.UTF_8));
        StringBuilder out = new StringBuilder();
        Base64.base64EncodeStandard(out, in, true);
        assertEquals("Zm9vYmE=", out.toString());
    }

    @Test
    public void testEncodeRfc6() {
        ByteArrayInputStream in = new ByteArrayInputStream("foobar".getBytes(StandardCharsets.UTF_8));
        StringBuilder out = new StringBuilder();
        Base64.base64EncodeStandard(out, in, true);
        assertEquals("Zm9vYmFy", out.toString());
    }

    @Test
    public void testEncodeAgainstPrecomputedValue() throws Exception {

        byte[] input = "Testing input of base64 function".getBytes("UTF-8");
        ByteStringBuilder encoded = new ByteStringBuilder();
        ByteStringBuilder decoded = new ByteStringBuilder();

        Base64.base64EncodeStandard(encoded, new ByteArrayInputStream(input), true);
        Assert.assertArrayEquals("VGVzdGluZyBpbnB1dCBvZiBiYXNlNjQgZnVuY3Rpb24=".getBytes(), encoded.toArray());

        Base64.base64DecodeStandard(encoded.toArray(), 0, decoded);
        Assert.assertArrayEquals(input, decoded.toArray());

    }


    /*
     * Standard Base64 alphabet decoding
     * (Expected values by http://www.freeformatter.com/base64-encoder.html)
     */

    @Test
    public void testDecodeBlank() throws Exception {
        char[] in = new char[]{};
        byte[] out = new byte[in.length * 3 / 4];
        CharacterArrayReader r = new CharacterArrayReader(in);
        Base64.base64DecodeStandard(r, out);
        r.close();
        Assert.assertArrayEquals(new byte[]{}, out);
        Assert.assertArrayEquals(new byte[]{}, Base64.base64DecodeStandard(in, 0));
    }

    @Test
    public void testDecodeWithoutPadding() throws Exception {
        char[] in = "YWJj".toCharArray();
        byte[] out = Base64.base64DecodeStandard(in, 0);
        assertEquals("abc", new String(out));
    }

    @Test
    public void testDecodeWith1Padding() throws Exception {
        char[] in = "YWI=".toCharArray();
        byte[] out = Base64.base64DecodeStandard(in, 0);
        assertEquals("ab", new String(out));
    }

    @Test
    public void testDecodeWith2Padding() throws Exception {
        char[] in = "YWJjZA==".toCharArray();
        byte[] out = Base64.base64DecodeStandard(in, 0);
        assertEquals("abcd", new String(out));
    }

    @Test
    public void testDecodeBinary() throws Exception {
        char[] in = "AAEjRWeJq83v".toCharArray();
        byte[] out = Base64.base64DecodeStandard(in, 0);
        Assert.assertArrayEquals(new byte[]{(byte)0x00,(byte)0x01,(byte)0x23,(byte)0x45,(byte)0x67,(byte)0x89,(byte)0xAB,(byte)0xCD,(byte)0xEF}, out);
    }

    @Test
    public void testDecodeRfc1() throws Exception {
        char[] in = "Zg==".toCharArray();
        byte[] out = Base64.base64DecodeStandard(in, 0);
        assertEquals("f", new String(out));
    }

    @Test
    public void testDecodeRfc2() throws Exception {
        char[] in = "Zm8=".toCharArray();
        byte[] out = Base64.base64DecodeStandard(in, 0);
        assertEquals("fo", new String(out));
    }

    @Test
    public void testDecodeRfc3() throws Exception {
        char[] in = "Zm9v".toCharArray();
        byte[] out = Base64.base64DecodeStandard(in, 0);
        assertEquals("foo", new String(out));
    }

    @Test
    public void testDecodeRfc4() throws Exception {
        char[] in = "Zm9vYg==".toCharArray();
        byte[] out = Base64.base64DecodeStandard(in, 0);
        assertEquals("foob", new String(out));
    }

    @Test
    public void testDecodeRfc5() throws Exception {
        char[] in = "Zm9vYmE=".toCharArray();
        byte[] out = Base64.base64DecodeStandard(in, 0);
        assertEquals("fooba", new String(out));
    }

    @Test
    public void testDecodeRfc6() throws Exception {
        char[] in = "Zm9vYmFy".toCharArray();
        byte[] out = Base64.base64DecodeStandard(in, 0);
        assertEquals("foobar", new String(out));
    }


    /*
     * Bcrypt Base64 alphabet encoding
     * (Expected values by php-litesec library - https://github.com/Jacques1/php-litesec/blob/master/src/password_hash.php)
     */

    @Test
    public void testBcryptEncodeF() {
        ByteArrayInputStream in = new ByteArrayInputStream("f".getBytes(StandardCharsets.UTF_8));
        StringBuilder out = new StringBuilder();
        Base64.base64EncodeBCrypt(out, in);
        assertEquals("Xe", out.toString());
    }

    @Test
    public void testBcryptEncodeFoobar() {
        ByteArrayInputStream in = new ByteArrayInputStream("foobar".getBytes(StandardCharsets.UTF_8));
        StringBuilder out = new StringBuilder();
        Base64.base64EncodeBCrypt(out, in);
        assertEquals("Xk7tWkDw", out.toString());
    }

    @Test
    public void testBcryptEncodeUnicode() {
        ByteArrayInputStream in = new ByteArrayInputStream("\u0000\u0054\u0123\u1234\uFEDC\uFFFF".getBytes(StandardCharsets.UTF_8));
        StringBuilder out = new StringBuilder();
        Base64.base64EncodeBCrypt(out, in);
        assertEquals(".DRCm8EGrM85lM89tu", out.toString());
    }


    /*
     * Bcrypt Base64 alphabet decoding
     * (Expected values by php-litesec library - https://github.com/Jacques1/php-litesec/blob/master/src/password_hash.php)
     */

    @Test
    public void testBcryptDecodeF() throws Exception {
        char[] in = "Xe".toCharArray();
        assertEquals(1, Base64.calculateDecodedLength(in, 0, in.length));
        CharacterArrayReader inr = new CharacterArrayReader(in);
        byte[] out = new byte[1];
        Base64.base64DecodeBCrypt(inr, out);
        inr.close();
        assertEquals("f", new String(out));
    }

    @Test
    public void testBcryptDecodeFoobar() throws Exception {
        char[] in = "Xk7tWkDw".toCharArray();
        assertEquals(6, Base64.calculateDecodedLength(in, 0, in.length));
        CharacterArrayReader inr = new CharacterArrayReader(in);
        byte[] out = new byte[6];
        Base64.base64DecodeBCrypt(inr, out);
        inr.close();
        assertEquals("foobar", new String(out));
    }

    @Test
    public void testBcryptDecodeUnicode() throws Exception {
        char[] in = ".DRCm8EGrM85lM89tu".toCharArray();
        assertEquals(13, Base64.calculateDecodedLength(in, 0, in.length));
        CharacterArrayReader inr = new CharacterArrayReader(in);
        byte[] out = new byte[13];
        Base64.base64DecodeBCrypt(inr, out);
        inr.close();
        assertArrayEquals(new byte[]{(byte)0x00,(byte)0x54,(byte)0xC4,(byte)0xA3,(byte)0xE1,(byte)0x88,(byte)0xB4,(byte)0xEF,(byte)0xBB,(byte)0x9C,(byte)0xEF,(byte)0xBF,(byte)0xBF}, out);
    }


    /*
     * ModCrypt Base64 alphabet encoding
     * (Expected values by https://github.com/magthe/sandi/blob/master/test-src/Codec/Binary/XxTest.hs)
     */

    @Test
    public void testModCryptEncodeF() {
        ByteArrayInputStream in = new ByteArrayInputStream("f".getBytes(StandardCharsets.UTF_8));
        StringBuilder out = new StringBuilder();
        Base64.base64EncodeModCrypt(out, in);
        assertEquals("NU", out.toString());
    }

    @Test
    public void testModCryptEncodeFo() {
        ByteArrayInputStream in = new ByteArrayInputStream("fo".getBytes(StandardCharsets.UTF_8));
        StringBuilder out = new StringBuilder();
        Base64.base64EncodeModCrypt(out, in);
        assertEquals("Naw", out.toString());
    }

    @Test
    public void testModCryptEncodeFoo() {
        ByteArrayInputStream in = new ByteArrayInputStream("foo".getBytes(StandardCharsets.UTF_8));
        StringBuilder out = new StringBuilder();
        Base64.base64EncodeModCrypt(out, in);
        assertEquals("Naxj", out.toString());
    }

    @Test
    public void testModCryptEncodeFoob() {
        ByteArrayInputStream in = new ByteArrayInputStream("foob".getBytes(StandardCharsets.UTF_8));
        StringBuilder out = new StringBuilder();
        Base64.base64EncodeModCrypt(out, in);
        assertEquals("NaxjMU", out.toString());
    }

    @Test
    public void testModCryptEncodeFooba() {
        ByteArrayInputStream in = new ByteArrayInputStream("fooba".getBytes(StandardCharsets.UTF_8));
        StringBuilder out = new StringBuilder();
        Base64.base64EncodeModCrypt(out, in);
        assertEquals("NaxjMa2", out.toString());
    }

    @Test
    public void testModCryptEncodeFoobar() {
        ByteArrayInputStream in = new ByteArrayInputStream("foobar".getBytes(StandardCharsets.UTF_8));
        StringBuilder out = new StringBuilder();
        Base64.base64EncodeModCrypt(out, in);
        assertEquals("NaxjMa3m", out.toString());
    }


    /*
     * ModCrypt Base64 alphabet decoding
     * (Expected values by https://github.com/magthe/sandi/blob/master/test-src/Codec/Binary/XxTest.hs)
     */

    @Test
    public void testModCryptDecodeF() throws Exception {
        char[] in = "NU".toCharArray();
        assertEquals(1, Base64.calculateDecodedLength(in, 0, in.length));
        CharacterArrayReader inr = new CharacterArrayReader(in);
        byte[] out = new byte[1];
        Base64.base64DecodeModCrypt(inr, out);
        inr.close();
        assertEquals("f", new String(out));
    }

    @Test
    public void testModCryptDecodeFo() throws Exception {
        char[] in = "Naw".toCharArray();
        assertEquals(2, Base64.calculateDecodedLength(in, 0, in.length));
        CharacterArrayReader inr = new CharacterArrayReader(in);
        byte[] out = new byte[2];
        Base64.base64DecodeModCrypt(inr, out);
        inr.close();
        assertEquals("fo", new String(out));
    }

    @Test
    public void testModCryptDecodeFoo() throws Exception {
        char[] in = "Naxj".toCharArray();
        assertEquals(3, Base64.calculateDecodedLength(in, 0, in.length));
        CharacterArrayReader inr = new CharacterArrayReader(in);
        byte[] out = new byte[3];
        Base64.base64DecodeModCrypt(inr, out);
        inr.close();
        assertEquals("foo", new String(out));
    }

    @Test
    public void testModCryptDecodeFoob() throws Exception {
        char[] in = "NaxjMU".toCharArray();
        assertEquals(4, Base64.calculateDecodedLength(in, 0, in.length));
        CharacterArrayReader inr = new CharacterArrayReader(in);
        byte[] out = new byte[4];
        Base64.base64DecodeModCrypt(inr, out);
        inr.close();
        assertEquals("foob", new String(out));
    }

    @Test
    public void testModCryptDecodeFooba() throws Exception {
        char[] in = "NaxjMa2".toCharArray();
        assertEquals(5, Base64.calculateDecodedLength(in, 0, in.length));
        CharacterArrayReader inr = new CharacterArrayReader(in);
        byte[] out = new byte[5];
        Base64.base64DecodeModCrypt(inr, out);
        inr.close();
        assertEquals("fooba", new String(out));
    }

    @Test
    public void testModCryptDecodeFoobar() throws Exception {
        char[] in = "NaxjMa3m".toCharArray();
        assertEquals(6, Base64.calculateDecodedLength(in, 0, in.length));
        CharacterArrayReader inr = new CharacterArrayReader(in);
        byte[] out = new byte[6];
        Base64.base64DecodeModCrypt(inr, out);
        inr.close();
        assertEquals("foobar", new String(out));
    }


    /*
     * ModCrypt LE Base64 alphabet encoding
     * (Expected values by https://github.com/olethanh/django-phpbb/blob/master/phpbb/password_unittest.py)
     */

    @Test
    public void testModCryptLeEncodeF() {
        ByteArrayInputStream in = new ByteArrayInputStream("f".getBytes(StandardCharsets.UTF_8));
        StringBuilder out = new StringBuilder();
        Base64.base64EncodeModCryptLE(out, in);
        assertEquals("a/", out.toString());
    }

    @Test
    public void testModCryptLeEncodeFoobar() {
        ByteArrayInputStream in = new ByteArrayInputStream("foobar".getBytes(StandardCharsets.UTF_8));
        StringBuilder out = new StringBuilder();
        Base64.base64EncodeModCryptLE(out, in);
        assertEquals("axqPW3aQ", out.toString());
    }


    /*
     * ModCrypt Base64 alphabet decoding
     * (Expected values by https://github.com/olethanh/django-phpbb/blob/master/phpbb/password_unittest.py)
     */

    @Test
    public void testModCryptLeDecodeF() throws Exception {
        char[] in = "a/".toCharArray();
        assertEquals(1, Base64.calculateDecodedLength(in, 0, in.length));
        CharacterArrayReader inr = new CharacterArrayReader(in);
        byte[] out = new byte[1];
        Base64.base64DecodeModCryptLE(inr, out, new int[]{0});
        inr.close();
        assertEquals("f", new String(out));
    }

    @Test
    public void testModCryptLeDecodeFoobar() throws Exception {
        char[] in = "axqPW3aQ".toCharArray();
        assertEquals(6, Base64.calculateDecodedLength(in, 0, in.length));
        CharacterArrayReader inr = new CharacterArrayReader(in);
        byte[] out = new byte[6];
        Base64.base64DecodeModCryptLE(inr, out, new int[]{0,1,2,3,4,5});
        inr.close();
        assertEquals("foobar", new String(out));
    }


    /*
     * Custom Base64 alphabet encoding
     * (Expected values based on known values from org.apache.commons.codec.binary.Base64Test with a URL safe alphabet)
     */

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


    /*
     * Custom Base64 alphabet decoding
     * (Expected values based on known values from org.apache.commons.codec.binary.Base64Test with a URL safe alphabet)
     */

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


    /*
     * Decoding of invalid input
     */

    @Test(expected=IllegalArgumentException.class)
    public void testInvalidInputDecodePadding1() throws Exception {
        char[] encoded = "=".toCharArray();
        Base64.base64DecodeStandard(encoded, 0, encoded.length);
    }

    @Test(expected=IllegalArgumentException.class)
    public void testInvalidInputDecodePadding2() throws Exception {
        char[] encoded = "==".toCharArray();
        Base64.base64DecodeStandard(encoded, 0, encoded.length);
    }

    @Test(expected=IllegalArgumentException.class)
    public void testInvalidInputDecodePadding3() throws Exception {
        char[] encoded = "===".toCharArray();
        Base64.base64DecodeStandard(encoded, 0, encoded.length);
    }

    @Test(expected=IllegalArgumentException.class)
    public void testInvalidInputDecodeNonalphabeticChar() throws Exception {
        char[] encoded = "áááááááááááá".toCharArray();
        Base64.base64DecodeStandard(encoded, 0, encoded.length);
    }

    @Test(expected=IllegalArgumentException.class)
    public void testInvalidInputDecodeTooMuchPadding() throws Exception {
        char[] encoded = "YWI==".toCharArray();
        Base64.base64DecodeStandard(encoded, 0, encoded.length);
    }


    /*
     * General Base64 tests
     */

    @Test
    public void testCalculateDecodedLength(){
        assertEquals(0, Base64.calculateDecodedLength("".toCharArray(), 0, 0));
        assertEquals(1, Base64.calculateDecodedLength("Zg".toCharArray(), 0, 2));
        assertEquals(1, Base64.calculateDecodedLength("Zg==".toCharArray(), 0, 4));
        assertEquals(2, Base64.calculateDecodedLength("Zm8".toCharArray(), 0, 3));
        assertEquals(2, Base64.calculateDecodedLength("Zm8=".toCharArray(), 0, 4));
        assertEquals(3, Base64.calculateDecodedLength("Zm9v".toCharArray(), 0, 4));
        assertEquals(4, Base64.calculateDecodedLength("Zm9vYg".toCharArray(), 0, 6));
        assertEquals(4, Base64.calculateDecodedLength("Zm9vYg==".toCharArray(), 0, 8));
        assertEquals(5, Base64.calculateDecodedLength("Zm9vYmE".toCharArray(), 0, 7));
        assertEquals(5, Base64.calculateDecodedLength("Zm9vYmE=".toCharArray(), 0, 8));
        assertEquals(6, Base64.calculateDecodedLength("Zm9vYmFy".toCharArray(), 0, 8));
    }

    @Test(expected=IllegalArgumentException.class)
    public void testCalculateDecodedLengthOfTooShort() throws Exception {
        Base64.calculateDecodedLength("=".toCharArray(), 0, 1);
    }

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
        ByteStringBuilder bsb = new ByteStringBuilder();
        Base64.base64EncodeStandard(bsb, new ByteArrayInputStream(inputData), true);

        byte[] result = bsb.toArray();
        assertTrue("Whole result data has to be within the range for base64", isInRange(result));
        assertEncodedLength(inputData.length, result.length);

        ByteStringBuilder afterDecode = new ByteStringBuilder();
        Base64.base64DecodeStandard(result, 0, afterDecode);

        assertArrayEquals("Encode-Decode test failed, results are not the same.", inputData, afterDecode.toArray());
    }

    private boolean isInRange(byte[] data) {
        for (int i = 0; i < data.length; i++) {
            if (data[i] == '=') { // padding - can be only at end of string
                if ((i != data.length - 1) && (i != data.length - 2)) {
                    return false;
                }
            } else { // in standard alphabet
                if (!((data[i] >= 'A' && data[i] <= 'Z') ||
                      (data[i] >= 'a' && data[i] <= 'z') ||
                      (data[i] >= '0' && data[i] <= '9') ||
                      (data[i] == '+') ||
                      (data[i] == '/') )) {
                    return false;
                }
            }
        }
        return true;
    }

    private void assertEncodedLength(int originalLen, int encodedLen) {

        int expectedLen;
        if (originalLen % 3 != 0) {
            expectedLen = (originalLen/3 + 1) * 4;
        } else {
            expectedLen = originalLen/3 * 4;
        }

        assertTrue("Encoded data are too long for base64 encoding ", encodedLen <= expectedLen);
    }

    private byte[] generateSequence(final int len) {
        byte[] data = new byte[len];
        for (int i = 0; i < len ; i++) {
            data[i] = (byte)i;
        }
        return data;
    }

}
