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

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import org.junit.Test;
import org.wildfly.security.password.interfaces.SunUnixMD5CryptPassword;
import org.wildfly.security.password.spec.EncryptablePasswordSpec;
import org.wildfly.security.password.spec.IteratedSaltedPasswordAlgorithmSpec;
import org.wildfly.security.password.util.ModularCrypt;

/**
 * Tests for the Sun variant of Unix MD5 Crypt. The expected results for
 * these test cases were generated using the {@code crypt} function from
 * the Python {@code crypt} module on a Sun Solaris 10 machine.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public class SunUnixMD5CryptTest {

    @Test
    public void testParseCryptStringWithoutRounds() throws NoSuchAlgorithmException, InvalidKeySpecException {
        String cryptString = "$md5$zrdhpMlZ$$wBvMOEqbSjU.hu5T2VEP01";

        // Get the spec by parsing the crypt string
        SunUnixMD5CryptPassword password = (SunUnixMD5CryptPassword) ModularCrypt.decode(cryptString);
        assertEquals(0, password.getIterationCount());

        // Use the spec to build a new crypt string and compare it to the original
        assertEquals(cryptString, ModularCrypt.encodeAsString(password));
    }

    @Test
    public void testParseCryptStringWithRounds() throws NoSuchAlgorithmException, InvalidKeySpecException {
        String cryptString = "$md5,rounds=1000$saltstring$$1wGsmnKgDGdu03LxKu0VI1";

        // Get the spec by parsing the crypt string
        SunUnixMD5CryptPassword password = (SunUnixMD5CryptPassword) ModularCrypt.decode(cryptString);
        assertEquals(1_000, password.getIterationCount());

        // Use the spec to build a new crypt string and compare it to the original
        assertEquals(cryptString, ModularCrypt.encodeAsString(password));
    }

    @Test
    public void testParseCryptStringWithBareSalt() throws NoSuchAlgorithmException, InvalidKeySpecException {
        String cryptString = "$md5,rounds=1500$saltstring$F9DNxgHVXWaeLS9zUaWXd.";

        // Get the spec by parsing the crypt string
        SunUnixMD5CryptPassword password = (SunUnixMD5CryptPassword) ModularCrypt.decode(cryptString);
        assertEquals(1_500, password.getIterationCount());

        // Use the spec to build a new crypt string and compare it to the original
        assertEquals(cryptString, ModularCrypt.encodeAsString(password));
    }

    private void generateAndVerify(String cryptString, String correctPassword) throws NoSuchAlgorithmException,  InvalidKeyException, InvalidKeySpecException {
        final PasswordFactorySpiImpl spi = new PasswordFactorySpiImpl();
        SunUnixMD5CryptPassword password = (SunUnixMD5CryptPassword) ModularCrypt.decode(cryptString);
        final String algorithm = password.getAlgorithm();

        // password is in raw form, need to translate first before verifying
        password = (SunUnixMD5CryptPassword) spi.engineTranslatePassword(algorithm, password);

        // Use the spec to generate a SunUnixMD5CryptPasswordImpl and then verify the hash using the correct password
        assertTrue(spi.engineVerify(algorithm, password, correctPassword.toCharArray()));
        assertFalse(spi.engineVerify(algorithm, password, "wrongpassword".toCharArray()));

        // Create a new password using EncryptablePasswordSpec and check if the hash matches the hash from the spec
        SunUnixMD5CryptPasswordImpl password2 = (SunUnixMD5CryptPasswordImpl) spi.engineGeneratePassword(algorithm,
                new EncryptablePasswordSpec(correctPassword.toCharArray(), new IteratedSaltedPasswordAlgorithmSpec(password.getIterationCount(), password.getSalt())));
        assertArrayEquals(password.getHash(), password2.getHash());

        // Use the new password to obtain a spec and then check if this spec yields the same crypt string
        assertEquals(cryptString, ModularCrypt.encodeAsString(password2));
    }

    @Test
    public void testHashEmptyPassword() throws NoSuchAlgorithmException,  InvalidKeyException, InvalidKeySpecException {
        String password = "";
        String cryptString = "$md5,rounds=10000$saltstring$$uwcsteApj7mCi4AIwYIT5.";
        generateAndVerify(cryptString, password);
    }

    @Test
    public void testHashEmptyPasswordWithBareSalt() throws NoSuchAlgorithmException,  InvalidKeyException, InvalidKeySpecException {
        String password = "";
        String cryptString = "$md5,rounds=10000$saltstring$gWOS3RRZtQ5TiYRg.vBx40";
        generateAndVerify(cryptString, password);
    }

    @Test
    public void testHashShortPassword() throws NoSuchAlgorithmException,  InvalidKeyException, InvalidKeySpecException {
        String password = "Hello world!";
        String cryptString = "$md5$saltstringsalt$$MsEJKkfiaflU4ioBHkqWe0";
        generateAndVerify(cryptString, password);
    }

    @Test
    public void testHashShortPasswordWithBareSalt() throws NoSuchAlgorithmException,  InvalidKeyException, InvalidKeySpecException {
        String password = "Hello world!";
        String cryptString = "$md5$saltstringsalt$uOXM5LLS7ZtN3eYYS54sM/";
        generateAndVerify(cryptString, password);
    }

    @Test
    public void testHashLongPassword() throws NoSuchAlgorithmException,  InvalidKeyException, InvalidKeySpecException {
        String password = "This is a very very very long password! This is the 2nd sentence in THE password. This is a test.@$%";
        String cryptString = "$md5,rounds=10000$saltstringsaltstring$$Occfaf7BttKIkRRUARiWU0";
        generateAndVerify(cryptString, password);
    }

    @Test
    public void testHashLongPasswordWithBareSalt() throws NoSuchAlgorithmException,  InvalidKeyException, InvalidKeySpecException {
        String password = "This is a very very very long password! This is the 2nd sentence in THE password. This is a test.@$%";
        String cryptString = "$md5,rounds=10000$saltstringsaltstring$0xbVBdJfPIual8oRvkU/f.";
        generateAndVerify(cryptString, password);
    }

    @Test
    public void testKnownCryptStrings() throws NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException {
        // Crypt string with bare salt
        generateAndVerify("$md5$RPgLF6IJ$WTvAlUJ7MqH5xak2FMEwS/", "passwd");

        // Crypt strings with "$$" after the salt
        generateAndVerify("$md5$zrdhpMlZ$$wBvMOEqbSjU.hu5T2VEP01", "Gpcs3_adm");
        generateAndVerify("$md5$vyy8.OVF$$FY4TWzuauRl4.VQNobqMY.", "aa12345678");
        generateAndVerify("$md5$3UqYqndY$$6P.aaWOoucxxq.l00SS9k0", "this");
    }
}
