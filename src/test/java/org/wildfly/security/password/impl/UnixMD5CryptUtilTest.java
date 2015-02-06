/*
 * JBoss, Home of Professional Open Source
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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import org.junit.Test;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordUtil;
import org.wildfly.security.password.interfaces.UnixMD5CryptPassword;
import org.wildfly.security.password.spec.EncryptablePasswordSpec;
import org.wildfly.security.password.spec.HashedPasswordAlgorithmSpec;
import org.wildfly.security.password.spec.UnixMD5CryptPasswordSpec;

/**
 * Tests for UnixMD5CryptUtil.
 * The expected results for these test cases were generated using the
 * {@code unix_md5_crypt} function from the {@code Crypt::PasswdMD5}
 * Perl module.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public class UnixMD5CryptUtilTest {

    @Test
    public void testParseCryptString() throws NoSuchAlgorithmException, InvalidKeySpecException {
        String cryptString = "$1$saltsalt$qjXMvbEw8oaL.CzflDtaK/";

        // Get the spec by parsing the crypt string
        UnixMD5CryptPasswordSpec spec = (UnixMD5CryptPasswordSpec) PasswordUtil.parseCryptString(cryptString);

        // Use the spec to build a new crypt string and compare it to the original
        assertEquals(cryptString, PasswordUtil.getCryptString(spec));
    }

    @Test
    public void testSaltTruncated() throws NoSuchAlgorithmException, InvalidKeySpecException {
        final String passwordStr = "password";
        byte[] salt = "thissaltstringistoolong".getBytes(StandardCharsets.UTF_8);

        // Create a new password using EncryptablePasswordSpec
        final PasswordFactorySpiImpl spi = new PasswordFactorySpiImpl();
        final Password password = spi.engineGeneratePassword(UnixMD5CryptPassword.ALGORITHM_CRYPT_MD5, new EncryptablePasswordSpec(passwordStr.toCharArray(), new HashedPasswordAlgorithmSpec(0, salt)));

        // Check if the salt was truncated in the resulting crypt string
        final String cryptString = PasswordUtil.getCryptString(spi.engineGetKeySpec(UnixMD5CryptPassword.ALGORITHM_CRYPT_MD5, password, UnixMD5CryptPasswordSpec.class));
        assertTrue("Didn't truncate the salt", cryptString.startsWith("$1$thissalt$"));
        assertEquals("$1$thissalt$B4AUaoQwRs3ex2F95O4ut/", cryptString);
    }

    private void generateAndVerify(String cryptString, String correctPassword) throws NoSuchAlgorithmException,  InvalidKeyException, InvalidKeySpecException {
        UnixMD5CryptPasswordSpec spec = (UnixMD5CryptPasswordSpec) PasswordUtil.parseCryptString(cryptString);

        // Use the spec to generate a UnixMD5CryptPasswordImpl and then verify the hash using the correct password
        final PasswordFactorySpiImpl spi = new PasswordFactorySpiImpl();
        UnixMD5CryptPasswordImpl password = (UnixMD5CryptPasswordImpl) spi.engineGeneratePassword(PasswordUtil.identifyAlgorithm(cryptString), spec);
        final String algorithm = password.getAlgorithm();
        assertTrue(spi.engineVerify(algorithm, password, correctPassword.toCharArray()));
        assertFalse(spi.engineVerify(algorithm, password, "wrongpassword".toCharArray()));

        // Create a new password using EncryptablePasswordSpec and check if the hash matches the hash from the spec
        UnixMD5CryptPasswordImpl password2 = (UnixMD5CryptPasswordImpl) spi.engineGeneratePassword(algorithm,
                new EncryptablePasswordSpec(correctPassword.toCharArray(), new HashedPasswordAlgorithmSpec(0, spec.getSalt())));
        assertArrayEquals(spec.getHash(), password2.getHash());

        // Use the new password to obtain a spec and then check if this spec yields the same crypt string
        spec = spi.engineGetKeySpec(PasswordUtil.identifyAlgorithm(cryptString), password2, UnixMD5CryptPasswordSpec.class);
        assertEquals(cryptString, PasswordUtil.getCryptString(spec));
    }

    @Test
    public void testEmptyPassword() throws NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException {
        String password = "";
        String cryptString = "$1$1234$.hKN8.QH1vHyGVLB072C0.";
        generateAndVerify(cryptString, password);
    }

    @Test
    public void testShortPassword() throws NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException {
        String password = "Hello world!";
        String cryptString = "$1$saltstri$YMyguxXMBpd2TEZ.vS/3q1";
        generateAndVerify(cryptString, password);
    }
    @Test
    public void testLongPassword() throws NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException {
        String password = "This is a very very very long password. This is another sentence in the password. This is a test.";
        String cryptString = "$1$saltstri$IQDu.vaa8hwk2UnOjF2PP.";
        generateAndVerify(cryptString, password);
    }

    @Test
    public void testCaseFromOriginalCImplementation() throws NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException {
        String password = "0.s0.l33t";
        String cryptString = "$1$deadbeef$0Huu6KHrKLVWfqa4WljDE0";
        generateAndVerify(cryptString, password);
    }
}
