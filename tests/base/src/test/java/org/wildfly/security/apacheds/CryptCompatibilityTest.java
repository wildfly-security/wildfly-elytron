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

package org.wildfly.security.apacheds;

import static org.junit.Assert.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;

import org.apache.directory.api.ldap.model.constants.LdapSecurityConstants;
import org.apache.directory.api.ldap.model.password.PasswordUtil;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.WildFlyElytronPasswordProvider;
import org.wildfly.security.password.interfaces.UnixDESCryptPassword;
import org.wildfly.security.password.util.ModularCrypt;

/**
 * A simple test case to verify that we can use an Apache DS generated {crypt} value with our {@link org.wildfly.security.password.interfaces.UnixDESCryptPassword UnixDESCryptPassword}
 * implementation. Note that Apache DS uses the standard Unix DES Crypt algorithm.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class CryptCompatibilityTest {

    private static final Provider provider = WildFlyElytronPasswordProvider.getInstance();

    @BeforeClass
    public static void register() {
        Security.addProvider(provider);
    }

    @AfterClass
    public static void remove() {
        Security.removeProvider(provider.getName());
    }

    private static final String PASSWORD = "cryptIt";
    private static final String LONG_PASSWORD = "cryptPassword"; // more than 8 characters

    @Test
    public void testComparison() throws InvalidKeySpecException, NoSuchAlgorithmException, InvalidKeyException {
        byte[] forStorage = PasswordUtil.createStoragePassword(PASSWORD.getBytes(StandardCharsets.UTF_8), LdapSecurityConstants.HASH_METHOD_CRYPT);

        System.out.println(new String(forStorage, StandardCharsets.UTF_8));

        UnixDESCryptPassword testPass = (UnixDESCryptPassword) ModularCrypt.createPassword(forStorage, UnixDESCryptPassword.ALGORITHM_CRYPT_DES);
        PasswordFactory pf = PasswordFactory.getInstance(UnixDESCryptPassword.ALGORITHM_CRYPT_DES);

        assertTrue(pf.verify(pf.translate(testPass), (PASSWORD).toCharArray()));
        System.out.println("Have something split out.");
    }

    @Test
    public void testComparisonWithLongPassword() throws InvalidKeySpecException, NoSuchAlgorithmException, InvalidKeyException {
        byte[] forStorage = PasswordUtil.createStoragePassword(LONG_PASSWORD.getBytes(StandardCharsets.UTF_8), LdapSecurityConstants.HASH_METHOD_CRYPT);

        System.out.println(new String(forStorage, StandardCharsets.UTF_8));

        UnixDESCryptPassword testPass = (UnixDESCryptPassword) ModularCrypt.createPassword(forStorage, UnixDESCryptPassword.ALGORITHM_CRYPT_DES);
        PasswordFactory pf = PasswordFactory.getInstance(UnixDESCryptPassword.ALGORITHM_CRYPT_DES);

        assertTrue(pf.verify(pf.translate(testPass), (LONG_PASSWORD).toCharArray()));
    }

}
