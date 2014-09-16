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
import static org.wildfly.security.password.interfaces.TrivialSaltedDigestPassword.ALGORITHM_PASSWORD_SALT_DIGEST_SHA_1;
import static org.wildfly.security.password.interfaces.TrivialSaltedDigestPassword.ALGORITHM_PASSWORD_SALT_DIGEST_SHA_256;
import static org.wildfly.security.password.interfaces.TrivialSaltedDigestPassword.ALGORITHM_PASSWORD_SALT_DIGEST_SHA_384;
import static org.wildfly.security.password.interfaces.TrivialSaltedDigestPassword.ALGORITHM_PASSWORD_SALT_DIGEST_SHA_512;
import static org.wildfly.security.password.interfaces.TrivialSaltedDigestPassword.ALGORITHM_SALT_PASSWORD_DIGEST_SHA_1;
import static org.wildfly.security.password.interfaces.TrivialSaltedDigestPassword.ALGORITHM_SALT_PASSWORD_DIGEST_SHA_256;
import static org.wildfly.security.password.interfaces.TrivialSaltedDigestPassword.ALGORITHM_SALT_PASSWORD_DIGEST_SHA_384;
import static org.wildfly.security.password.interfaces.TrivialSaltedDigestPassword.ALGORITHM_SALT_PASSWORD_DIGEST_SHA_512;

import java.nio.charset.StandardCharsets;
import java.security.Provider;
import java.security.Security;
import java.util.Arrays;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.interfaces.TrivialSaltedDigestPassword;
import org.wildfly.security.password.spec.EncryptablePasswordSpec;
import org.wildfly.security.password.spec.SaltedPasswordAlgorithmSpec;
import org.wildfly.security.password.spec.TrivialSaltedDigestPasswordSpec;
import org.wildfly.security.util.Base64;
import org.wildfly.security.util.CharacterArrayReader;

/**
 * Test case for the {@link TrivialSaledDigestPassword} implementation.
 *
 * This test deliberately avoids testing storage representations and parsing capabilities as those are realm specific instead
 * this test focuses on the use of the Elytron APIs for the handling of this password type.
 *
 * For the purpose of testing a constant salt of 'salt' is used, along with a constant password of 'password'.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class TrivialSaltedDigestPasswordTest {

    private static final byte[] salt = "salt".getBytes(StandardCharsets.UTF_8);
    private static final char[] password = "password".toCharArray();

    private static final Provider provider = new WildFlyElytronPasswordProvider();

    @BeforeClass
    public static void registerProvider() {
        Security.addProvider(provider);
    }

    @AfterClass
    public static void removeProvider() {
        Security.removeProvider(provider.getName());
    }

    @Test
    public void testPasswordSaltSha1() throws Exception {
        performTest(ALGORITHM_PASSWORD_SALT_DIGEST_SHA_1, "yI6cZwQadOA1e+/f+T+H3eCQQhQ".toCharArray());
    }

    @Test
    public void testPasswordSaltSha256() throws Exception {
        performTest(ALGORITHM_PASSWORD_SALT_DIGEST_SHA_256, "eje4XIkY6sGakInA+loqtNzj+QUo3N7sEIsj3fNge5k".toCharArray());
    }

    @Test
    public void testPasswordSaltSha384() throws Exception {
        performTest(ALGORITHM_PASSWORD_SALT_DIGEST_SHA_384,
                "JhBd8taJ7iy7c13rUwqdA0BiYlK+mbYtvmYKgUUH/Hnzlu9+YBTxYd973pJ5gvjP".toCharArray());
    }

    @Test
    public void testPasswordSaltSha512() throws Exception {
        performTest(ALGORITHM_PASSWORD_SALT_DIGEST_SHA_512,
                "+mohhbPgqahe9B/7Z+88H7b3SYD46/lw5OcuNT7ZU31ZMIPCAd/W5D4cinqsK8jbsRnH37fUuPExEROVvXDpfw".toCharArray());
    }

    @Test
    public void testSaltPasswordSha1() throws Exception {
        performTest(ALGORITHM_SALT_PASSWORD_DIGEST_SHA_1, "WbPo1jfPl+2+I4TPWct0U9/jB4k".toCharArray());
    }

    @Test
    public void testSaltPasswordSha256() throws Exception {
        performTest(ALGORITHM_SALT_PASSWORD_DIGEST_SHA_256, "E2Ab2k6njlWge5iGbSvmvgdE44ZvE8AMgRyrYIoo8yI".toCharArray());
    }

    @Test
    public void testSaltPasswordSha384() throws Exception {
        performTest(ALGORITHM_SALT_PASSWORD_DIGEST_SHA_384,
                "9L2smGDAzupp+ynvvOJK3cpc8fgIkl2UM7ZoUoKQ1dLJCA8yNCF1tRJIlWhNuLpP".toCharArray());
    }

    @Test
    public void testSaltPasswordSha512() throws Exception {
        performTest(ALGORITHM_SALT_PASSWORD_DIGEST_SHA_512,
                "KQjSwo38BHdB/FkKAm/63iN6srp+EmbwEP5JveVItZh6U0qGZVoNF/M2WI5UDNZvZyNLFSu7ZFtLuFdYoTJdZA".toCharArray());
    }

    /**
     * Perform a test for the specified algorithm with the pre-prepared digest for that algorithm.
     *
     * @param algorithmName the agorithm to use to perform a test.
     * @param base64Digest the Base64 representation of the expected digest for this algorithm.
     */
    private void performTest(final String algorithmName, final char[] base64Digest) throws Exception {
        byte[] preDigested = new byte[base64Digest.length * 3 / 4];
        CharacterArrayReader r = new CharacterArrayReader(base64Digest);
        Base64.base64DecodeB(r, preDigested);
        r.close();

        PasswordFactory pf = PasswordFactory.getInstance(algorithmName);
        // Encryptable Spec -> Password
        SaltedPasswordAlgorithmSpec spac = new SaltedPasswordAlgorithmSpec(salt);
        EncryptablePasswordSpec eps = new EncryptablePasswordSpec(password, spac);

        TrivialSaltedDigestPassword tsdp = (TrivialSaltedDigestPassword) pf.generatePassword(eps);

        validatePassword(tsdp, preDigested, pf);

        assertTrue("Convertable to key spec", pf.convertibleToKeySpec(tsdp, TrivialSaltedDigestPasswordSpec.class));
        TrivialSaltedDigestPasswordSpec tsdps = pf.getKeySpec(tsdp, TrivialSaltedDigestPasswordSpec.class);
        assertTrue("Salt Correctly Passed", Arrays.equals(salt, tsdps.getSalt()));
        assertTrue("Digest Correctly Generated", Arrays.equals(preDigested, tsdps.getDigest()));

        // Digest into Spec -> Password
        tsdps = new TrivialSaltedDigestPasswordSpec(algorithmName, preDigested, salt);
        tsdp = (TrivialSaltedDigestPassword) pf.generatePassword(tsdps);

        validatePassword(tsdp, preDigested, pf);

        // Custom TrivialSaltedDigestPassword implementation.
        TestPasswordImpl tpi = new TestPasswordImpl(algorithmName, salt, preDigested);
        tsdp = (TrivialSaltedDigestPassword) pf.translate(tpi);

        validatePassword(tsdp, preDigested, pf);
    }

    private void validatePassword(TrivialSaltedDigestPassword tsdp, byte[] preDigested, PasswordFactory pf) throws Exception {
        assertTrue("Salt Correctly Passed", Arrays.equals(salt, tsdp.getSalt()));
        assertTrue("Digest Correctly Generated", Arrays.equals(preDigested, tsdp.getDigest()));

        assertTrue("Password Validation", pf.verify(tsdp, password));
        assertFalse("Bad Password Rejection", pf.verify(tsdp, "bad".toCharArray()));
    }

    private class TestPasswordImpl implements TrivialSaltedDigestPassword {

        private final String algorithm;
        private final byte[] salt;
        private final byte[] digest;

        private TestPasswordImpl(final String algorithm, final byte[] salt, final byte[] digest) {
            this.algorithm = algorithm;
            this.salt = salt;
            this.digest = digest;
        }

        @Override
        public String getAlgorithm() {
            return algorithm;
        }

        @Override
        public String getFormat() {
            return null;
        }

        @Override
        public byte[] getEncoded() {
            return new byte[0];
        }

        @Override
        public byte[] getDigest() {
            return digest;
        }

        @Override
        public byte[] getSalt() {
            return salt;
        }

    }

}
