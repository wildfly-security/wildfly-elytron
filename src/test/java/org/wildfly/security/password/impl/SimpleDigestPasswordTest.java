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

package org.wildfly.security.password.impl;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.wildfly.security.password.interfaces.SimpleDigestPassword.ALGORITHM_SIMPLE_DIGEST_MD2;
import static org.wildfly.security.password.interfaces.SimpleDigestPassword.ALGORITHM_SIMPLE_DIGEST_MD5;
import static org.wildfly.security.password.interfaces.SimpleDigestPassword.ALGORITHM_SIMPLE_DIGEST_SHA_1;
import static org.wildfly.security.password.interfaces.SimpleDigestPassword.ALGORITHM_SIMPLE_DIGEST_SHA_256;
import static org.wildfly.security.password.interfaces.SimpleDigestPassword.ALGORITHM_SIMPLE_DIGEST_SHA_384;
import static org.wildfly.security.password.interfaces.SimpleDigestPassword.ALGORITHM_SIMPLE_DIGEST_SHA_512;

import java.security.Provider;
import java.security.Security;
import java.util.Arrays;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.wildfly.common.iteration.CodePointIterator;
import org.wildfly.security.WildFlyElytronProvider;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.interfaces.SimpleDigestPassword;
import org.wildfly.security.password.spec.EncryptablePasswordSpec;
import org.wildfly.security.password.spec.HashPasswordSpec;

/**
 * Test of SimpleDigestPasswordImpl
 */
public class SimpleDigestPasswordTest {

    private static final Provider provider = new WildFlyElytronProvider();

    @BeforeClass
    public static void registerProvider() {
        Security.addProvider(provider);
    }

    @AfterClass
    public static void removeProvider() {
        Security.removeProvider(provider.getName());
    }

    /**
     * Test of MD2 - reference values from RFC1319
     */
    @Test
    public void testPasswordMD2() throws Exception {
        performTest(ALGORITHM_SIMPLE_DIGEST_MD2, "".toCharArray(), "8350e5a3e24c153df2275c9f80692773");
        performTest(ALGORITHM_SIMPLE_DIGEST_MD2, "abc".toCharArray(), "da853b0d3f88d99b30283a69e6ded6bb");
        performTest(ALGORITHM_SIMPLE_DIGEST_MD2, "message digest".toCharArray(), "ab4f496bfb2a530b219ff33031fe06b0");
        performTest(ALGORITHM_SIMPLE_DIGEST_MD2, "abcdefghijklmnopqrstuvwxyz".toCharArray(), "4e8ddff3650292ab5a4108c3aa47940b");
        performTest(ALGORITHM_SIMPLE_DIGEST_MD2, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".toCharArray(), "da33def2a42df13975352846c30338cd");
        performTest(ALGORITHM_SIMPLE_DIGEST_MD2, "12345678901234567890123456789012345678901234567890123456789012345678901234567890".toCharArray(), "d5976f79d83d3a0dc9806c3c66f3efd8");
    }

    /**
     * Test of MD5 - reference values from RFC1321
     */
    @Test
    public void testPasswordMD5() throws Exception {
        performTest(ALGORITHM_SIMPLE_DIGEST_MD5, "".toCharArray(), "d41d8cd98f00b204e9800998ecf8427e");
        performTest(ALGORITHM_SIMPLE_DIGEST_MD5, "a".toCharArray(), "0cc175b9c0f1b6a831c399e269772661");
        performTest(ALGORITHM_SIMPLE_DIGEST_MD5, "abc".toCharArray(), "900150983cd24fb0d6963f7d28e17f72");
        performTest(ALGORITHM_SIMPLE_DIGEST_MD5, "message digest".toCharArray(), "f96b697d7cb7938d525a2f31aaf161d0");
        performTest(ALGORITHM_SIMPLE_DIGEST_MD5, "abcdefghijklmnopqrstuvwxyz".toCharArray(), "c3fcd3d76192e4007dfb496cca67e13b");
        performTest(ALGORITHM_SIMPLE_DIGEST_MD5, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".toCharArray(), "d174ab98d277d9f5a5611c2c9f419d9f");
        performTest(ALGORITHM_SIMPLE_DIGEST_MD5, "12345678901234567890123456789012345678901234567890123456789012345678901234567890".toCharArray(), "57edf4a22be3c955ac49da2e2107b67a");
    }

    /**
     * Test of SHA1
     */
    @Test
    public void testPasswordSHA1() throws Exception {
        performTest(ALGORITHM_SIMPLE_DIGEST_SHA_1, "".toCharArray(), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        performTest(ALGORITHM_SIMPLE_DIGEST_SHA_1, "a".toCharArray(), "86f7e437faa5a7fce15d1ddcb9eaeaea377667b8");
        performTest(ALGORITHM_SIMPLE_DIGEST_SHA_1, "abc".toCharArray(), "a9993e364706816aba3e25717850c26c9cd0d89d");
        performTest(ALGORITHM_SIMPLE_DIGEST_SHA_1, "abcdefghijklmnopqrstuvwxyz".toCharArray(), "32d10c7b8cf96570ca04ce37f2a19d84240d3a89");
    }

    /**
     * Test of SHA256
     */
    @Test
    public void testPasswordSHA256() throws Exception {
        performTest(ALGORITHM_SIMPLE_DIGEST_SHA_256, "".toCharArray(), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        performTest(ALGORITHM_SIMPLE_DIGEST_SHA_256, "a".toCharArray(), "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb");
        performTest(ALGORITHM_SIMPLE_DIGEST_SHA_256, "abc".toCharArray(), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        performTest(ALGORITHM_SIMPLE_DIGEST_SHA_256, "abcdefghijklmnopqrstuvwxyz".toCharArray(), "71c480df93d6ae2f1efad1447c66c9525e316218cf51fc8d9ed832f2daf18b73");
    }

    /**
     * Test of SHA384
     */
    @Test
    public void testPasswordSHA384() throws Exception {
        performTest(ALGORITHM_SIMPLE_DIGEST_SHA_384, "".toCharArray(), "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b");
        performTest(ALGORITHM_SIMPLE_DIGEST_SHA_384, "a".toCharArray(), "54a59b9f22b0b80880d8427e548b7c23abd873486e1f035dce9cd697e85175033caa88e6d57bc35efae0b5afd3145f31");
        performTest(ALGORITHM_SIMPLE_DIGEST_SHA_384, "abc".toCharArray(), "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7");
        performTest(ALGORITHM_SIMPLE_DIGEST_SHA_384, "abcdefghijklmnopqrstuvwxyz".toCharArray(), "feb67349df3db6f5924815d6c3dc133f091809213731fe5c7b5f4999e463479ff2877f5f2936fa63bb43784b12f3ebb4");
    }

    /**
     * Test of SHA512
     */
    @Test
    public void testPasswordSHA512() throws Exception {
        performTest(ALGORITHM_SIMPLE_DIGEST_SHA_512, "".toCharArray(), "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
        performTest(ALGORITHM_SIMPLE_DIGEST_SHA_512, "a".toCharArray(), "1f40fc92da241694750979ee6cf582f2d5d7d28e18335de05abc54d0560e0f5302860c652bf08d560252aa5e74210546f369fbbbce8c12cfc7957b2652fe9a75");
        performTest(ALGORITHM_SIMPLE_DIGEST_SHA_512, "abc".toCharArray(), "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
        performTest(ALGORITHM_SIMPLE_DIGEST_SHA_512, "abcdefghijklmnopqrstuvwxyz".toCharArray(), "4dbff86cc2ca1bae1e16468a05cb9881c97f1753bce3619034898faa1aabe429955a1bf8ec483d7421fe3c1646613a59ed5441fb0f321389f77f48a879c7b1f1");
    }

    /**
     * Perform a test for the specified algorithm with the pre-prepared digest for that algorithm.
     *
     * @param algorithmName the algorithm to use to perform a test
     * @param password expected password characters
     * @param hexDigest hexadecimal representation of expected password digest
     */
    private void performTest(final String algorithmName, char[] password, String hexDigest) throws Exception {
        byte[] preDigested = CodePointIterator.ofString(hexDigest).hexDecode().drain();

        PasswordFactory factory = PasswordFactory.getInstance(algorithmName);
        EncryptablePasswordSpec encryptableSpec = new EncryptablePasswordSpec(password, null);

        SimpleDigestPassword simplePassword = (SimpleDigestPassword) factory.generatePassword(encryptableSpec);

        validatePassword(simplePassword, password, preDigested, factory);

        assertTrue("Convertable to key spec", factory.convertibleToKeySpec(simplePassword, HashPasswordSpec.class));
        HashPasswordSpec simpleSpec = factory.getKeySpec(simplePassword, HashPasswordSpec.class);
        assertTrue("Digest Correctly Generated", Arrays.equals(preDigested, simpleSpec.getDigest()));

        simpleSpec = new HashPasswordSpec(preDigested);
        simplePassword = (SimpleDigestPassword) factory.generatePassword(simpleSpec);

        validatePassword(simplePassword, password, preDigested, factory);
    }

    private void validatePassword(SimpleDigestPassword simplePassword, char[] password, byte[] preDigested, PasswordFactory factory) throws Exception {
        Assert.assertArrayEquals(preDigested, simplePassword.getDigest());

        assertTrue("Password Validation", factory.verify(simplePassword, password));
        assertFalse("Bad Password Rejection", factory.verify(simplePassword, "bad".toCharArray()));
    }
}
