/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2017 Red Hat, Inc., and individual contributors
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

import java.nio.charset.StandardCharsets;

import org.junit.Test;
import org.wildfly.common.iteration.ByteIterator;
import org.wildfly.common.iteration.CodePointIterator;
import org.wildfly.security.password.util.ModularCrypt;

/**
 * Tests of encoding/decoding Base64 B (standard alphabet)
 * implemented in org.wildfly.security.util.Base64
 *
 * @author <a href="mailto:jkalina@redhat.com">Jan Kalina</a>
 */
public class Base64Test {

    /*
     * Bcrypt Base64 alphabet encoding
     * (Expected values by php-litesec library - https://github.com/Jacques1/php-litesec/blob/master/src/password_hash.php)
     */

    @Test
    public void testBcryptEncodeF() {
        assertEquals("Xe", CodePointIterator.ofString("f").asLatin1().base64Encode(ModularCrypt.BCRYPT, false).drainToString());
    }

    @Test
    public void testBcryptEncodeFoobar() {
        assertEquals("Xk7tWkDw", CodePointIterator.ofString("foobar").asLatin1().base64Encode(ModularCrypt.BCRYPT, false).drainToString());
    }

    @Test
    public void testBcryptEncodeUnicode() {
        assertEquals(".DRCm8EGrM85lM89tu", CodePointIterator.ofString("\u0000\u0054\u0123\u1234\uFEDC\uFFFF").asUtf8().base64Encode(ModularCrypt.BCRYPT, false).drainToString());
    }


    /*
     * Bcrypt Base64 alphabet decoding
     * (Expected values by php-litesec library - https://github.com/Jacques1/php-litesec/blob/master/src/password_hash.php)
     */

    @Test
    public void testBcryptDecodeF() throws Exception {
        assertEquals("f", CodePointIterator.ofString("Xe").base64Decode(ModularCrypt.BCRYPT, false).asUtf8String().drainToString());
    }

    @Test
    public void testBcryptDecodeFoobar() throws Exception {
        assertEquals("foobar", CodePointIterator.ofString("Xk7tWkDw").base64Decode(ModularCrypt.BCRYPT, false).asUtf8String().drainToString());
    }

    @Test
    public void testBcryptDecodeUnicode() throws Exception {
        String in = ".DRCm8EGrM85lM89tu";
        assertArrayEquals(new byte[]{(byte)0x00,(byte)0x54,(byte)0xC4,(byte)0xA3,(byte)0xE1,(byte)0x88,(byte)0xB4,(byte)0xEF,(byte)0xBB,(byte)0x9C,(byte)0xEF,(byte)0xBF,(byte)0xBF}, CodePointIterator.ofString(in).base64Decode(ModularCrypt.BCRYPT, false).drain());
    }


    /*
     * ModCrypt Base64 alphabet encoding
     * (Expected values by https://github.com/magthe/sandi/blob/master/test-src/Codec/Binary/XxTest.hs)
     */

    @Test
    public void testModCryptEncodeF() {
        assertEquals("NU", ByteIterator.ofBytes("f".getBytes(StandardCharsets.UTF_8)).base64Encode(ModularCrypt.MOD_CRYPT, false).drainToString());
    }

    @Test
    public void testModCryptEncodeFo() {
        assertEquals("Naw", ByteIterator.ofBytes("fo".getBytes(StandardCharsets.UTF_8)).base64Encode(ModularCrypt.MOD_CRYPT, false).drainToString());
    }

    @Test
    public void testModCryptEncodeFoo() {
        assertEquals("Naxj", ByteIterator.ofBytes("foo".getBytes(StandardCharsets.UTF_8)).base64Encode(ModularCrypt.MOD_CRYPT, false).drainToString());
    }

    @Test
    public void testModCryptEncodeFoob() {
        assertEquals("NaxjMU", ByteIterator.ofBytes("foob".getBytes(StandardCharsets.UTF_8)).base64Encode(ModularCrypt.MOD_CRYPT, false).drainToString());
    }

    @Test
    public void testModCryptEncodeFooba() {
        assertEquals("NaxjMa2", ByteIterator.ofBytes("fooba".getBytes(StandardCharsets.UTF_8)).base64Encode(ModularCrypt.MOD_CRYPT, false).drainToString());
    }

    @Test
    public void testModCryptEncodeFoobar() {
        assertEquals("NaxjMa3m", ByteIterator.ofBytes("foobar".getBytes(StandardCharsets.UTF_8)).base64Encode(ModularCrypt.MOD_CRYPT, false).drainToString());
    }


    /*
     * ModCrypt Base64 alphabet decoding
     * (Expected values by https://github.com/magthe/sandi/blob/master/test-src/Codec/Binary/XxTest.hs)
     */

    @Test
    public void testModCryptDecodeF() throws Exception {
        assertEquals("f", CodePointIterator.ofString("NU").base64Decode(ModularCrypt.MOD_CRYPT, false).asUtf8String().drainToString());
    }

    @Test
    public void testModCryptDecodeFo() throws Exception {
        assertEquals("fo", CodePointIterator.ofString("Naw").base64Decode(ModularCrypt.MOD_CRYPT, false).asUtf8String().drainToString());
    }

    @Test
    public void testModCryptDecodeFoo() throws Exception {
        assertEquals("foo", CodePointIterator.ofString("Naxj").base64Decode(ModularCrypt.MOD_CRYPT, false).asUtf8String().drainToString());
    }

    @Test
    public void testModCryptDecodeFoob() throws Exception {
        assertEquals("foob", CodePointIterator.ofString("NaxjMU").base64Decode(ModularCrypt.MOD_CRYPT, false).asUtf8String().drainToString());
    }

    @Test
    public void testModCryptDecodeFooba() throws Exception {
        assertEquals("fooba", CodePointIterator.ofString("NaxjMa2").base64Decode(ModularCrypt.MOD_CRYPT, false).asUtf8String().drainToString());
    }

    @Test
    public void testModCryptDecodeFoobar() throws Exception {
        assertEquals("foobar", CodePointIterator.ofString("NaxjMa3m").base64Decode(ModularCrypt.MOD_CRYPT, false).asUtf8String().drainToString());
    }


    /*
     * ModCrypt LE Base64 alphabet encoding
     * (Expected values by https://github.com/olethanh/django-phpbb/blob/master/phpbb/password_unittest.py)
     */

    @Test
    public void testModCryptLeEncodeF() {
        assertEquals("a/", CodePointIterator.ofString("f").asLatin1().base64Encode(ModularCrypt.MOD_CRYPT_LE, false).drainToString());
    }

    @Test
    public void testModCryptLeEncodeFoobar() {
        assertEquals("axqPW3aQ", CodePointIterator.ofString("foobar").asLatin1().base64Encode(ModularCrypt.MOD_CRYPT_LE, false).drainToString());
    }


    /*
     * ModCrypt Base64 alphabet decoding
     * (Expected values by https://github.com/olethanh/django-phpbb/blob/master/phpbb/password_unittest.py)
     */

    @Test
    public void testModCryptLeDecodeF() throws Exception {
        assertEquals("f", CodePointIterator.ofChars("a/".toCharArray()).base64Decode(ModularCrypt.MOD_CRYPT_LE, false).asUtf8String().drainToString());
    }

    @Test
    public void testModCryptLeDecodeFoobar() throws Exception {
        assertEquals("foobar", CodePointIterator.ofChars("axqPW3aQ".toCharArray()).base64Decode(ModularCrypt.MOD_CRYPT_LE, false).asUtf8String().drainToString());
    }
}
