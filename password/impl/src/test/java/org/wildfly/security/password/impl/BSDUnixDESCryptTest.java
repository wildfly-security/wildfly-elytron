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
import java.security.spec.InvalidKeySpecException;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.wildfly.security.password.interfaces.BSDUnixDESCryptPassword;
import org.wildfly.security.password.spec.EncryptablePasswordSpec;
import org.wildfly.security.password.spec.IteratedSaltedPasswordAlgorithmSpec;
import org.wildfly.security.password.spec.IteratedSaltedHashPasswordSpec;
import org.wildfly.security.password.spec.PasswordSpec;
import org.wildfly.security.password.spec.SaltedHashPasswordSpec;
import org.wildfly.security.password.util.ModularCrypt;

/**
 * Tests for the BSD variant of Unix DES Crypt.
 * The expected results for these test cases were generated using the
 * {@code crypt} function from the {@code Crypt::UnixCrypt_XS}
 * Perl module.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public class BSDUnixDESCryptTest {

    @Rule
    public ExpectedException exception = ExpectedException.none();

    @Test
    public void testGeneratePasswordWithInvalidKeySpec() throws InvalidKeySpecException {
        final PasswordFactorySpiImpl spi = new PasswordFactorySpiImpl();

        // Create a BSDUnixDESCryptPasswordSpec with an invalid hash
        IteratedSaltedHashPasswordSpec invalidSpec = new IteratedSaltedHashPasswordSpec(new byte[4], new byte[] { 0, 0, 10 }, 100);

        // An InvalidKeySpecException should be thrown when creating a BSDUnixDESCryptPassword using the invalid spec
        exception.expect(InvalidKeySpecException.class);
        exception.expectMessage("BSD DES crypt password hash must be 8 bytes");
        BSDUnixDESCryptPasswordImpl password = (BSDUnixDESCryptPasswordImpl) spi.engineGeneratePassword(BSDUnixDESCryptPassword.ALGORITHM_BSD_CRYPT_DES, invalidSpec);
    }

    @Test
    public void testGeneratePasswordWithInvalidParameterSpec() throws InvalidKeySpecException {
        final PasswordFactorySpiImpl spi = new PasswordFactorySpiImpl();

        // Create an EncryptablePasswordSpec with an invalid salt
        byte[] salt = new byte[2];
        salt[0] = (byte) 10;
        salt[1] = (byte) 20;
        EncryptablePasswordSpec invalidSpec = new EncryptablePasswordSpec("password".toCharArray(), new IteratedSaltedPasswordAlgorithmSpec(100, salt));

        // An InvalidKeySpecException should be thrown when creating a BSDUnixDESCryptPassword using the invalid spec
        exception.expect(InvalidKeySpecException.class);
        exception.expectMessage("Salt must be 3 bytes");
        BSDUnixDESCryptPasswordImpl password = (BSDUnixDESCryptPasswordImpl) spi.engineGeneratePassword(BSDUnixDESCryptPassword.ALGORITHM_BSD_CRYPT_DES, invalidSpec);
    }

    @Test
    public void testGetKeySpecWithInvalidKeySpecType() throws InvalidKeySpecException {
        final PasswordFactorySpiImpl spi = new PasswordFactorySpiImpl();

        // Create a BSDUnixDESCryptPasswordImpl using EncryptablePasswordSpec
        int saltInt = 10914278;
        byte[] salt = new byte[3];
        salt[0] = (byte) (saltInt >> 16);
        salt[1] = (byte) (saltInt >> 8);
        salt[2] = (byte) (saltInt);
        BSDUnixDESCryptPasswordImpl password = (BSDUnixDESCryptPasswordImpl) spi.engineGeneratePassword(BSDUnixDESCryptPassword.ALGORITHM_BSD_CRYPT_DES,
                new EncryptablePasswordSpec("password".toCharArray(), new IteratedSaltedPasswordAlgorithmSpec(100, salt)));

        // Use the new password to obtain a spec but specify an invalid key spec type
        exception.expect(InvalidKeySpecException.class);
        PasswordSpec spec = spi.engineGetKeySpec(BSDUnixDESCryptPassword.ALGORITHM_BSD_CRYPT_DES, password, SaltedHashPasswordSpec.class);
    }

    @Test
    public void testConvertibleToKeySpec() throws InvalidKeySpecException {
        final PasswordFactorySpiImpl spi = new PasswordFactorySpiImpl();

        // Create a BSDUnixDESCryptPasswordImpl using EncryptablePasswordSpec
        int saltInt = 10914278;
        byte[] salt = new byte[3];
        salt[0] = (byte) (saltInt >> 16);
        salt[1] = (byte) (saltInt >> 8);
        salt[2] = (byte) (saltInt);
        BSDUnixDESCryptPasswordImpl password = (BSDUnixDESCryptPasswordImpl) spi.engineGeneratePassword(BSDUnixDESCryptPassword.ALGORITHM_BSD_CRYPT_DES,
                new EncryptablePasswordSpec("password".toCharArray(), new IteratedSaltedPasswordAlgorithmSpec(100, salt)));

        // The new password should only be convertible to IteratedSaltedHashPasswordSpec
        assertTrue(spi.engineConvertibleToKeySpec(BSDUnixDESCryptPassword.ALGORITHM_BSD_CRYPT_DES, password, IteratedSaltedHashPasswordSpec.class));
    }

    @Test
    public void testParseCryptString() throws InvalidKeySpecException {
        String cryptString = "_rH..saltodLocONXC9c";

        // Get the spec by parsing the crypt string
        BSDUnixDESCryptPassword password = (BSDUnixDESCryptPassword) ModularCrypt.decode(cryptString);
        assertEquals(1_271, password.getIterationCount());
        assertEquals(BSDUnixDESCryptPassword.BSD_CRYPT_DES_HASH_SIZE, password.getHash().length);

        // Use the spec to build a new crypt string and compare it to the original
        assertEquals(cryptString, ModularCrypt.encodeAsString(password));
    }

    private void generateAndVerify(String cryptString, String correctPassword) throws InvalidKeyException, InvalidKeySpecException {
        final PasswordFactorySpiImpl spi = new PasswordFactorySpiImpl();
        BSDUnixDESCryptPassword password = (BSDUnixDESCryptPassword) ModularCrypt.decode(cryptString);
        final String algorithm = password.getAlgorithm();

        // password is in raw form, need to translate first before verifying
        password = (BSDUnixDESCryptPassword) spi.engineTranslatePassword(algorithm, password);

        // Use the spec to generate a BSDUnixDESCryptPasswordImpl and then verify the hash
        // using the correct password
        assertTrue(spi.engineVerify(algorithm, password, correctPassword.toCharArray()));
        assertFalse(spi.engineVerify(algorithm, password, "wrongpassword".toCharArray()));

        // Create a new password using EncryptablePasswordSpec and check if the hash matches
        // the hash from the spec
        byte[] salt = new byte[3];
        salt[0] = (byte) (password.getSalt() >> 16);
        salt[1] = (byte) (password.getSalt() >> 8);
        salt[2] = (byte) (password.getSalt());
        BSDUnixDESCryptPasswordImpl password2 = (BSDUnixDESCryptPasswordImpl) spi.engineGeneratePassword(algorithm,
                new EncryptablePasswordSpec(correctPassword.toCharArray(), new IteratedSaltedPasswordAlgorithmSpec(password.getIterationCount(), salt)));
        assertEquals(password.getSalt(), password2.getSalt());
        assertArrayEquals(password.getHash(), password2.getHash());

        // Use the new password to obtain a spec and then check if this spec yields the same
        // crypt string
        assertEquals(cryptString, ModularCrypt.encodeAsString(password2));
    }

    @Test
    public void testHashEmptyPassword() throws InvalidKeyException, InvalidKeySpecException {
        String password = "";
        String cryptString = "_RL..sAlTyrFYtms.HA6";
        generateAndVerify(cryptString, password);
    }

    @Test
    public void testHashShortPassword() throws InvalidKeyException, InvalidKeySpecException {
        String password = "abcdef*";
        String cryptString = "_JI../5cPYU9MP8zM5nM";
        generateAndVerify(cryptString, password);
    }

    @Test
    public void testHashLongPassword() throws InvalidKeyException, InvalidKeySpecException {
        String password = "*!%^& This is the very first sentence in this password! &()+ This is the 2nd sentence in THE password. This is a test.@$%";
        String cryptString = "_lG..4.P9QWI6xTfHq9.";
        generateAndVerify(cryptString, password);
    }

    @Test
    public void testKnownCryptStrings() throws InvalidKeyException, InvalidKeySpecException {
        generateAndVerify("_K1..crsmZxOLzfJH8iw", " ");
        generateAndVerify("_KR/.crsmykRplHbAvwA", "my");
        generateAndVerify("_K1..crsmf/9NzZr1fLM", "my socra");
        generateAndVerify("_K1..crsmOv1rbde9A9o", "my socrates");
        generateAndVerify("_K1..crsm/2qeAhdISMA", "my socrates note");
        generateAndVerify("_J9..XXXXVL7qJCnku0I", "*U*U*U*U*U*U*U*U");
        generateAndVerify("_J9..XXXXAj8cFbP5scI", "*U*U*U*U*U*U*U*U*");
    }

    @Test
    public void testInvalidIterationCount() throws InvalidKeySpecException {
        final PasswordFactorySpiImpl spi = new PasswordFactorySpiImpl();

        // Create an EncryptablePasswordSpec with an invalid number of rounds
        int saltInt = 10914278;
        byte[] salt = new byte[3];
        salt[0] = (byte) (saltInt >> 16);
        salt[1] = (byte) (saltInt >> 8);
        salt[2] = (byte) (saltInt);
        EncryptablePasswordSpec invalidSpec = new EncryptablePasswordSpec("password".toCharArray(), new IteratedSaltedPasswordAlgorithmSpec(17_777_200, salt));

        // An IllegalArgumentException should occur when creating a BSDUnixDESCryptPasswordImpl using the invalid spec
        exception.expect(InvalidKeySpecException.class);
        exception.expectMessage("Invalid number of rounds. Must be an integer between 1 and 16777215, inclusive");
        BSDUnixDESCryptPasswordImpl password = (BSDUnixDESCryptPasswordImpl) spi.engineGeneratePassword(BSDUnixDESCryptPassword.ALGORITHM_BSD_CRYPT_DES, invalidSpec);
    }
}
