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

import static org.junit.Assert.*;

import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;

import org.junit.Test;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordUtil;
import org.wildfly.security.password.interfaces.UnixDESCryptPassword;
import org.wildfly.security.password.spec.EncryptablePasswordSpec;
import org.wildfly.security.password.spec.HashedPasswordAlgorithmSpec;
import org.wildfly.security.password.spec.UnixDESCryptPasswordSpec;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public class UnixCryptTest {

    @Test
    public void testBasicString() throws InvalidKeySpecException, InvalidKeyException {
        final PasswordFactorySpiImpl spi = new PasswordFactorySpiImpl();
        final Password password = spi.engineGeneratePassword("crypt-des", new EncryptablePasswordSpec("test".toCharArray(), new HashedPasswordAlgorithmSpec(0, null)));
        assertTrue(spi.engineVerify("crypt-des", password, "test".toCharArray()));
        assertFalse(spi.engineVerify("crypt-des", password, "test_".toCharArray()));
        assertFalse(spi.engineVerify("crypt-des", password, "test_foo_bar".toCharArray()));
    }

    @Test
    public void testParse() throws InvalidKeySpecException {
        final UnixDESCryptPasswordSpec spec = (UnixDESCryptPasswordSpec) PasswordUtil.parseCryptString("ABwOg1D2JDxIQ");
        final PasswordFactorySpiImpl spi = new PasswordFactorySpiImpl();
        byte[] salt = new byte[2];
        salt[0] = (byte) (spec.getSalt() >> 8);
        salt[1] = (byte) (spec.getSalt() >> 0);
        assertEquals("ABwOg1D2JDxIQ", PasswordUtil.getCryptString(spec));
        final UnixDESCryptPassword p2 = (UnixDESCryptPassword) spi.engineGeneratePassword("crypt-des", new EncryptablePasswordSpec("test".toCharArray(), new HashedPasswordAlgorithmSpec(0, salt)));
        assertEquals("Salts unmatched", spec.getSalt(), p2.getSalt());
        assertEquals("ABwOg1D2JDxIQ", PasswordUtil.getCryptString(spi.engineGetKeySpec("crypt-des", p2, UnixDESCryptPasswordSpec.class)));
    }

    @Test
    public void testKnownStrings() throws InvalidKeySpecException, InvalidKeyException {
        PasswordFactorySpiImpl spi = new PasswordFactorySpiImpl();
        assertTrue(spi.engineVerify("crypt-des", spi.engineGeneratePassword("crypt-des", PasswordUtil.parseCryptString("xyf/bMLia/2RU")), "testtest".toCharArray()));
        assertTrue(spi.engineVerify("crypt-des", spi.engineGeneratePassword("crypt-des", PasswordUtil.parseCryptString("ABwOg1D2JDxIQ")), "test".toCharArray()));
        assertTrue(spi.engineVerify("crypt-des", spi.engineGeneratePassword("crypt-des", PasswordUtil.parseCryptString("./derspCn2Kmo")), "testtestextra".toCharArray()));
    }
}
