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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import org.junit.Test;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordUtils;
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
    public void testSaltTruncated() throws NoSuchAlgorithmException, InvalidKeySpecException {
        String result = getEncoded("password", "thissaltstringistoolong");
        assertTrue("Didn't truncate the salt", result.startsWith("$1$thissalt$"));
        assertEquals("$1$thissalt$B4AUaoQwRs3ex2F95O4ut/", result);
    }

    @Test
    public void testEmptyPassword() throws NoSuchAlgorithmException, InvalidKeySpecException {
        String result = getEncoded("", "1234");
        assertEquals("$1$1234$.hKN8.QH1vHyGVLB072C0.", result);
    }

    @Test
    public void testShortPassword() throws NoSuchAlgorithmException, InvalidKeySpecException {
        String result = getEncoded("Hello world!", "saltstring");
        assertEquals("$1$saltstri$YMyguxXMBpd2TEZ.vS/3q1", result);
    }
    @Test
    public void testLongPassword() throws NoSuchAlgorithmException, InvalidKeySpecException {
        String password = "This is a very very very long password. This is another sentence in the password. This is a test.";
        String salt = "saltstringsaltstring";
        String result = getEncoded(password, salt);
        assertEquals("$1$saltstri$IQDu.vaa8hwk2UnOjF2PP.", result);
    }

    @Test
    public void testCaseFromOriginalCImplementation() throws NoSuchAlgorithmException, InvalidKeySpecException {
        String result = getEncoded("0.s0.l33t", "deadbeef");
        assertEquals("$1$deadbeef$0Huu6KHrKLVWfqa4WljDE0", result);
    }

    private String getEncoded(String passwordStr, String saltStr) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] salt = saltStr.getBytes(StandardCharsets.UTF_8);
        final PasswordFactorySpiImpl spi = new PasswordFactorySpiImpl();
        final Password password = spi.engineGeneratePassword(UnixMD5CryptPassword.ALGORITHM_MD5_CRYPT, new EncryptablePasswordSpec(passwordStr.toCharArray(), new HashedPasswordAlgorithmSpec(0, salt)));
        return PasswordUtils.getCryptString(spi.engineGetKeySpec(UnixMD5CryptPassword.ALGORITHM_MD5_CRYPT, password, UnixMD5CryptPasswordSpec.class));
    }
}
