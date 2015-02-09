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

import static org.wildfly.security.password.interfaces.BCryptPassword.*;

import java.security.Provider;
import java.security.Security;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.PasswordUtil;
import org.wildfly.security.password.interfaces.BCryptPassword;
import org.wildfly.security.password.spec.BCryptPasswordSpec;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.password.spec.EncryptablePasswordSpec;
import org.wildfly.security.password.spec.HashedPasswordAlgorithmSpec;

/**
 * <p>
 * Tests for the bcrypt password implementation. The expected results in the tests were generated using the
 * <a href="http://www.mindrot.org/projects/jBCrypt/">jBCrypt project</a>.
 * </p>
 *
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 */
public class BCryptPasswordTest {

    private static final Provider provider = new WildFlyElytronPasswordProvider();

    @BeforeClass
    public static void setup() {
        Security.addProvider(provider);
    }

    @AfterClass
    public static void removeProvider() {
        Security.removeProvider(provider.getName());
    }

    @Test
    public void testGetKeySpecFromString() throws Exception {
        String cryptString = "$2a$12$D4G5f18o7aMMfwasBL7GpuQWuP3pkrZrOAnqP.bmezbMng.QwJ/pG";

        // get the spec by parsing the crypt string.
        BCryptPasswordSpec spec = (BCryptPasswordSpec) PasswordUtil.parseCryptString(cryptString);
        Assert.assertEquals(12, spec.getIterationCount());
        Assert.assertEquals(BCryptPassword.BCRYPT_SALT_SIZE, spec.getSalt().length);

        // use the spec to build a new crypt string and compare it to the original one.
        Assert.assertEquals(cryptString, PasswordUtil.getCryptString(spec));
    }

    @Test
    public void testHashEmptyString() throws Exception {
        String cryptString = "$2a$08$HqWuK6/Ng6sg9gQzbLrgb.Tl.ZHfXLhvt/SgVyWhQqgqcZ7ZuUtye";
        BCryptPasswordSpec spec = (BCryptPasswordSpec) PasswordUtil.parseCryptString(cryptString);
        PasswordFactory factory = PasswordFactory.getInstance(ALGORITHM_BCRYPT);

        // use the obtained spec to build a BCryptPasswordImpl, then verify the hash using the correct password.
        BCryptPassword password = (BCryptPassword) factory.generatePassword(spec);
        Assert.assertTrue(factory.verify(password, "".toCharArray()));

        // check if an incorrect password gets rejected.
        Assert.assertFalse(factory.verify(password, "wrongpassword".toCharArray()));

        // now use the EncryptablePasswordSpec to build a new password and check if the hashed bytes matches those that
        // were parsed and stored in the spec.
        password = (BCryptPassword) factory.generatePassword(new EncryptablePasswordSpec("".toCharArray(),
                new HashedPasswordAlgorithmSpec(spec.getIterationCount(), spec.getSalt())));
        Assert.assertArrayEquals(spec.getHashBytes(), password.getHash());

        // use the new password to obtain a spec and then check if the spec yields the same crypt string.
        spec = factory.getKeySpec(password, BCryptPasswordSpec.class);
        Assert.assertEquals(cryptString, PasswordUtil.getCryptString(spec));
    }

    @Test
    public void testHashSimpleString() throws Exception {
        String cryptString = "$2a$10$fVH8e28OQRj9tqiDXs1e1uxpsjN0c7II7YPKXua2NAKYvM6iQk7dq";
        char[] correctPassword = "abcdefghijklmnopqrstuvwxyz".toCharArray();
        BCryptPasswordSpec spec = (BCryptPasswordSpec) PasswordUtil.parseCryptString(cryptString);
        PasswordFactory factory = PasswordFactory.getInstance(ALGORITHM_BCRYPT);

        // use the obtained spec to build a BCryptPasswordImpl, then verify the hash using the correct password.
        BCryptPassword password = (BCryptPassword) factory.generatePassword(spec);
        Assert.assertTrue(factory.verify(password, correctPassword));

        // check if an incorrect password gets rejected.
        Assert.assertFalse(factory.verify(password, "wrongpassword".toCharArray()));

        // now use the EncryptablePasswordSpec to build a new password and check if the hashed bytes matches those that
        // were parsed and stored in the spec.
        password = (BCryptPassword) factory.generatePassword(new EncryptablePasswordSpec(correctPassword,
                new HashedPasswordAlgorithmSpec(spec.getIterationCount(), spec.getSalt())));
        Assert.assertArrayEquals(spec.getHashBytes(), password.getHash());

        // use the new password to obtain a spec and then check if the spec yields the same crypt string.
        spec = factory.getKeySpec(password, BCryptPasswordSpec.class);
        Assert.assertEquals(cryptString, PasswordUtil.getCryptString(spec));
    }

    @Test
    public void testHashComplexString() throws Exception {
        String cryptString = "$2a$12$WApznUOJfkEGSmYRfnkrPOr466oFDCaj4b6HY3EXGvfxm43seyhgC";
        char[] correctPassword = "~!@#$%^&*()      ~!@#$%^&*()PNBFRD".toCharArray();
        BCryptPasswordSpec spec = (BCryptPasswordSpec) PasswordUtil.parseCryptString(cryptString);
        PasswordFactory factory = PasswordFactory.getInstance(ALGORITHM_BCRYPT);

        // use the obtained spec to build a BCryptPasswordImpl, then verify the hash using the correct password.
        BCryptPassword password = (BCryptPassword) factory.generatePassword(spec);
        Assert.assertTrue(factory.verify(password, correctPassword));

        // check if an incorrect password gets rejected.
        Assert.assertFalse(factory.verify(password, "wrongpassword".toCharArray()));

        // now use the EncryptablePasswordSpec to build a new password and check if the hashed bytes matches those that
        // were parsed and stored in the spec.
        password = (BCryptPassword) factory.generatePassword(new EncryptablePasswordSpec(correctPassword,
                new HashedPasswordAlgorithmSpec(spec.getIterationCount(), spec.getSalt())));
        Assert.assertArrayEquals(spec.getHashBytes(), password.getHash());

        // use the new password to obtain a spec and then check if the spec yields the same crypt string.
        spec = factory.getKeySpec(password, BCryptPasswordSpec.class);
        Assert.assertEquals(cryptString, PasswordUtil.getCryptString(spec));
    }

    /**
     * <p>
     * Test the usage of a {@link org.wildfly.security.password.spec.ClearPasswordSpec} to hash a password. A random
     * salt should be generated and the default iteration count should be used.
     * </p>
     *
     * @throws Exception if an error occurs while running the test.
     */
    @Test
    public void testHashClearPassword() throws Exception {
        PasswordFactory factory = PasswordFactory.getInstance(ALGORITHM_BCRYPT);
        ClearPasswordSpec spec = new ClearPasswordSpec("password".toCharArray());
        BCryptPassword password = (BCryptPassword) factory.generatePassword(spec);

        // check if a salt has been generated and if the default iteration count is being used.
        BCryptPasswordSpec bcryptSpec = factory.getKeySpec(password, BCryptPasswordSpec.class);
        Assert.assertNotNull(bcryptSpec.getSalt());
        Assert.assertEquals(BCRYPT_SALT_SIZE, bcryptSpec.getSalt().length);
        Assert.assertEquals(DEFAULT_ITERATION_COUNT, bcryptSpec.getIterationCount());

        // check if the correct password is verified while an incorrect password is rejected.
        Assert.assertTrue(factory.verify(password, "password".toCharArray()));
        Assert.assertFalse(factory.verify(password, "wrongpassword".toCharArray()));
    }

    /**
     * <p>
     * For this test the crypt string was generated using the Python PassLib bcrypt implementation.
     * </p>
     *
     * @throws Exception if an error occurs while running the test.
     */
    @Test
    public void testHashAgainstPassLib() throws Exception {
        String cryptString = "$2a$12$NT0I31Sa7ihGEWpka9ASYeEFkhuTNeBQ2xfZskIiiJeyFXhRgS.Sy";
        char[] correctPassword = "password".toCharArray();
        BCryptPasswordSpec spec = (BCryptPasswordSpec) PasswordUtil.parseCryptString(cryptString);
        PasswordFactory factory = PasswordFactory.getInstance(ALGORITHM_BCRYPT);

        // use the obtained spec to build a BCryptPasswordImpl, then verify the hash using the correct password.
        BCryptPassword password = (BCryptPassword) factory.generatePassword(spec);
        Assert.assertTrue(factory.verify(password, correctPassword));

        // check if an incorrect password gets rejected.
        Assert.assertFalse(factory.verify(password, "wrongpassword".toCharArray()));

        // now use the EncryptablePasswordSpec to build a new password and check if the hashed bytes matches those that
        // were parsed and stored in the spec.
        password = (BCryptPassword) factory.generatePassword(new EncryptablePasswordSpec(correctPassword,
                new HashedPasswordAlgorithmSpec(spec.getIterationCount(), spec.getSalt())));
        Assert.assertArrayEquals(spec.getHashBytes(), password.getHash());

        // use the new password to obtain a spec and then check if the spec yields the same crypt string.
        spec = factory.getKeySpec(password, BCryptPasswordSpec.class);
        Assert.assertEquals(cryptString, PasswordUtil.getCryptString(spec));
    }

    @Test
    public void testLongKeys() throws Exception {
        byte[] salt = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                       0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
        PasswordFactory factory = PasswordFactory.getInstance(ALGORITHM_BCRYPT);

        // hash a password that is too long (size > 72 bytes).
        String longKey = "01234567890123456789012345678901234567890123456789012345678901234567890123456789";
        BCryptPassword password = (BCryptPassword) factory.generatePassword(
                new EncryptablePasswordSpec(longKey.toCharArray(), new HashedPasswordAlgorithmSpec(6, salt)));

        // another long password that shares the first 72 bytes with the original password should yield the same hash.
        String longKeyAlt = "012345678901234567890123456789012345678901234567890123456789012345678901xxxxxxxxyyyyzzzzzz";
        Assert.assertTrue(factory.verify(password, longKeyAlt.toCharArray()));
    }
}
