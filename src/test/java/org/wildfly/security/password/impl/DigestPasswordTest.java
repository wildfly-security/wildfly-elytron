/*
 * JBoss, Home of Professional Open Source
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

package org.wildfly.security.password.impl;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.wildfly.security.password.interfaces.DigestPassword.ALGORITHM_DIGEST_MD5;
import static org.wildfly.security.password.interfaces.DigestPassword.ALGORITHM_DIGEST_SHA;
import static org.wildfly.security.password.interfaces.DigestPassword.ALGORITHM_DIGEST_SHA_256;
import static org.wildfly.security.password.interfaces.DigestPassword.ALGORITHM_DIGEST_SHA_384;
import static org.wildfly.security.password.interfaces.DigestPassword.ALGORITHM_DIGEST_SHA_512;
import static org.wildfly.security.password.interfaces.DigestPassword.ALGORITHM_DIGEST_SHA_512_256;

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
import org.wildfly.security.password.interfaces.DigestPassword;
import org.wildfly.security.password.spec.DigestPasswordAlgorithmSpec;
import org.wildfly.security.password.spec.DigestPasswordSpec;
import org.wildfly.security.password.spec.EncryptablePasswordSpec;

/**
 * Test case for {@link DigestPassword}.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class DigestPasswordTest {

    private static final String USERNAME = "username";
    private static final String REALM = "realm";
    private static final String PASSWORD = "password";

    private static final Provider provider = new WildFlyElytronProvider();

    @BeforeClass
    public static void registerProvider() {
        Security.addProvider(provider);
    }

    @AfterClass
    public static void removeProvider() {
        Security.removeProvider(provider.getName());
    }

    @Test
    public void testMD5() throws Exception {
        performTest(ALGORITHM_DIGEST_MD5, "66999343281b2624585fd58cc9d36dfc");
    }

    @Test
    public void testSHA() throws Exception {
        performTest(ALGORITHM_DIGEST_SHA, "df127c363b43d097a6007c94adc2dfdb37eaf5d5");
    }

    @Test
    public void testSHA256() throws Exception {
        performTest(ALGORITHM_DIGEST_SHA_256, "220a5eadca08cfb9523ff67b0e40f63909864a124b71584bf2b28ae8538f1150");
    }

    @Test
    public void testSHA384() throws Exception {
        performTest(ALGORITHM_DIGEST_SHA_384, "3f1e6e07e78fbca5f9ffc25703cb523a29fb4dc0f43a539e44b81de2dfb24dd943e955ed3e4ae46c578456a6edb20d47");
    }

    @Test
    public void testSHA512() throws Exception {
        performTest(ALGORITHM_DIGEST_SHA_512, "b55e7d5d719b4ac1917abae97fa309e639fd86a9dfbd9e5807c196c3f483c19ddfd74d9b56b995d2b2493ed66b65b9015b95daeff76275a7b2bf42121676bc34");
    }

    @Test
    public void testSHA512_256() throws Exception {
        performTest(ALGORITHM_DIGEST_SHA_512_256, "524bfc3ed0cb625f5ce11074b833dbbc337d36bce866fcc48d84cd1f60fddf63");
    }

    private void performTest(final String algorithm, final String expectedHexDigest) throws Exception {
        byte[] preDigested = CodePointIterator.ofString(expectedHexDigest).hexDecode().drain();

        PasswordFactory factory = PasswordFactory.getInstance(algorithm);
        DigestPasswordAlgorithmSpec dpas = new DigestPasswordAlgorithmSpec(USERNAME, REALM);
        EncryptablePasswordSpec encryptableSpec = new EncryptablePasswordSpec(PASSWORD.toCharArray(), dpas);

        DigestPassword digestPassword = (DigestPassword) factory.generatePassword(encryptableSpec);

        validatePassword(digestPassword, PASSWORD, preDigested, factory);

        assertTrue("Convertable to key spec", factory.convertibleToKeySpec(digestPassword, DigestPasswordSpec.class));
        DigestPasswordSpec digestSpec = factory.getKeySpec(digestPassword, DigestPasswordSpec.class);
        assertTrue("Digest Correctly Generated", Arrays.equals(preDigested, digestSpec.getDigest()));

        digestSpec = new DigestPasswordSpec(USERNAME, REALM, preDigested);
        digestPassword = (DigestPassword) factory.generatePassword(digestSpec);

        validatePassword(digestPassword, PASSWORD, preDigested, factory);
    }

    private void validatePassword(DigestPassword simplePassword, String password, byte[] preDigested, PasswordFactory factory) throws Exception {
        Assert.assertArrayEquals(preDigested, simplePassword.getDigest());

        assertTrue("Password Validation", factory.verify(simplePassword, password.toCharArray()));
        assertFalse("Bad Password Rejection", factory.verify(simplePassword, "bad".toCharArray()));
    }
}
