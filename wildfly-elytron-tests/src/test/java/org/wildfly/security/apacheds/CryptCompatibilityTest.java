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

import java.nio.ByteBuffer;
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
import org.wildfly.common.iteration.CodePointIterator;
import org.wildfly.security.WildFlyElytronProvider;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.interfaces.UnixDESCryptPassword;
import org.wildfly.security.password.spec.SaltedHashPasswordSpec;
import org.wildfly.security.password.util.ModularCrypt;

/**
 * A simple test case to verify that we can use an Apache DS generated {crypt} value with our {@link org.wildfly.security.password.interfaces.UnixDESCryptPassword UnixDESCryptPassword}
 * implementation. Note that Apache DS uses the standard Unix DES Crypt algorithm.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class CryptCompatibilityTest {

    private static final Provider provider = new WildFlyElytronProvider();

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

        byte[] saltBytes = new byte[2];
        byte[] digestBase64 = new byte[forStorage.length - 9];

        System.arraycopy(forStorage, 7, saltBytes, 0, 2);
        System.arraycopy(forStorage, 9, digestBase64, 0, digestBase64.length);

        final short salt = (short) convertSaltRepresentation(saltBytes);

        byte[] digest = CodePointIterator.ofUtf8Bytes(digestBase64).base64Decode(ModularCrypt.MOD_CRYPT, false).drain();

        SaltedHashPasswordSpec spec = new SaltedHashPasswordSpec(digest, ByteBuffer.allocate(2).putShort(salt).array());

        PasswordFactory pf = PasswordFactory.getInstance(UnixDESCryptPassword.ALGORITHM_CRYPT_DES);
        UnixDESCryptPassword password = (UnixDESCryptPassword) pf.generatePassword(spec);

        assertTrue(pf.verify(password, (PASSWORD).toCharArray()));
        System.out.println("Have something split out.");
    }

    @Test
    public void testComparisonWithLongPassword() throws InvalidKeySpecException, NoSuchAlgorithmException, InvalidKeyException {
        byte[] forStorage = PasswordUtil.createStoragePassword(LONG_PASSWORD.getBytes(StandardCharsets.UTF_8), LdapSecurityConstants.HASH_METHOD_CRYPT);

        System.out.println(new String(forStorage, StandardCharsets.UTF_8));

        byte[] saltBytes = new byte[2];
        byte[] digestBase64 = new byte[forStorage.length - 9];

        System.arraycopy(forStorage, 7, saltBytes, 0, 2);
        System.arraycopy(forStorage, 9, digestBase64, 0, digestBase64.length);

        final short salt = (short) convertSaltRepresentation(saltBytes);

        byte[] digest = CodePointIterator.ofUtf8Bytes(digestBase64).base64Decode(ModularCrypt.MOD_CRYPT, false).drain();

        SaltedHashPasswordSpec spec = new SaltedHashPasswordSpec(digest, ByteBuffer.allocate(2).putShort(salt).array());

        PasswordFactory pf = PasswordFactory.getInstance(UnixDESCryptPassword.ALGORITHM_CRYPT_DES);
        UnixDESCryptPassword password = (UnixDESCryptPassword) pf.generatePassword(spec);

        assertTrue(pf.verify(password, (LONG_PASSWORD).toCharArray()));
    }

    private static int convertSaltRepresentation(final byte[] saltBytes) throws InvalidKeySpecException {
        int salt = 0;

        for (int i = 1; i >= 0; i--) {
            salt = ( salt << 6 ) | ( 0x00ff & ModularCrypt.MOD_CRYPT.decode(saltBytes[i]));
        }

        return salt;
    }

}
