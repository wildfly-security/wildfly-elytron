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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.wildfly.security.password.interfaces.ScramDigestPassword.ALGORITHM_SCRAM_SHA_1;
import static org.wildfly.security.password.interfaces.ScramDigestPassword.ALGORITHM_SCRAM_SHA_256;

import java.nio.charset.StandardCharsets;
import java.security.Provider;
import java.security.Security;
import java.util.Arrays;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.wildfly.common.codec.Base64Alphabet;
import org.wildfly.common.iteration.ByteIterator;
import org.wildfly.common.iteration.CodePointIterator;
import org.wildfly.security.WildFlyElytronProvider;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.interfaces.ScramDigestPassword;
import org.wildfly.security.password.spec.EncryptablePasswordSpec;
import org.wildfly.security.password.spec.IteratedSaltedPasswordAlgorithmSpec;
import org.wildfly.security.password.spec.IteratedSaltedHashPasswordSpec;

/**
 * <p>
 * Tests for the SCRAM password implementation. The Base64-encoded digests and salts used in the tests were generated
 * by the Python Passlib scram hash function.
 * </p>
 *
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 */

public class ScramDigestPasswordTest {

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
    public void testBasicFunctionality() throws Exception {
        byte[] digest;
        IteratedSaltedHashPasswordSpec spec;
        ScramDigestPasswordImpl impl;

        digest = ScramDigestPasswordImpl.scramDigest(ALGORITHM_SCRAM_SHA_1, "password".getBytes(StandardCharsets.UTF_8), "salt".getBytes(StandardCharsets.UTF_8), 4096);
        assertEquals("4b007901b765489abead49d926f721d065a429c1", ByteIterator.ofBytes(digest).hexEncode().drainToString());
        spec = new IteratedSaltedHashPasswordSpec(digest, "salt".getBytes(StandardCharsets.UTF_8), 4096);
        impl = new ScramDigestPasswordImpl(ALGORITHM_SCRAM_SHA_1, spec);
        assertTrue(impl.verify("password".toCharArray()));
        assertFalse(impl.verify("bad".toCharArray()));

        digest = ScramDigestPasswordImpl.scramDigest(ALGORITHM_SCRAM_SHA_256, "password".getBytes(StandardCharsets.UTF_8), "salt".getBytes(StandardCharsets.UTF_8), 1000);
        assertEquals("632c2812e46d4604102ba7618e9d6d7d2f8128f6266b4a03264d2a0460b7dcb3", ByteIterator.ofBytes(digest).hexEncode().drainToString());
        spec = new IteratedSaltedHashPasswordSpec(digest, "salt".getBytes(StandardCharsets.UTF_8), 1000);
        impl = new ScramDigestPasswordImpl(ALGORITHM_SCRAM_SHA_256, spec);
        assertTrue(impl.verify("password".toCharArray()));
        assertFalse(impl.verify("bad".toCharArray()));
    }

    /**
     * Test of PBKDF2 with SHA-1
     * <p>
     * Reference values by:
     * <li> http://www.ietf.org/rfc/rfc6070.txt
     * <li> http://www.neurotechnics.com/tools/xpassword
     */
    @Test
    public void testDigestSha1() throws Exception {
        this.performTest(ALGORITHM_SCRAM_SHA_1, "password", "0c60c80f961f0e71f3a9b524af6012062fe037a6", "salt", 1);
        this.performTest(ALGORITHM_SCRAM_SHA_1, "password", "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957", "salt", 2);
        this.performTest(ALGORITHM_SCRAM_SHA_1, "password", "4b007901b765489abead49d926f721d065a429c1", "salt", 4096);
        this.performTest(ALGORITHM_SCRAM_SHA_1, "passwordPASSWORDpassword", "3d2eec4fe41c849b80c8d83662c0e44a8b291a96", "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096);
        this.performTest(ALGORITHM_SCRAM_SHA_1, "This is little longer password, used for testing of SCRAM digest password hashing.", "e99c31f453b4801a0951f4e9f7b289b01a54743e", "6e81991f001e5c568b05384d50b4159badf9f3b3e288d1e222c5a7cf599c1974", 1000);
        this.performTest(ALGORITHM_SCRAM_SHA_1, "a\u0438\u4F60\uD83C\uDCA1", "569c650be201904269bf160d52c426dcacda7521", "\uD83C\uDCA1\u4F60\u0438a", 4096);
    }

    /**
     * Test of PBKDF2 with SHA-256
     * <p>
     * Reference values by:
     * <li> https://github.com/ircmaxell/PHP-PasswordLib/blob/master/test/Data/Vectors/pbkdf2-draft-josefsson-sha256.test-vectors
     * <li> http://www.neurotechnics.com/tools/xpassword
     */
    @Test
    public void testDigestSha256() throws Exception {
        this.performTest(ALGORITHM_SCRAM_SHA_256, "password", "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b", "salt", 1);
        this.performTest(ALGORITHM_SCRAM_SHA_256, "password", "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43", "salt", 2);
        this.performTest(ALGORITHM_SCRAM_SHA_256, "password", "ad35240ac683febfaf3cd49d845473fbbbaa2437f5f82d5a415ae00ac76c6bfc", "salt", 3);
        this.performTest(ALGORITHM_SCRAM_SHA_256, "password", "632c2812e46d4604102ba7618e9d6d7d2f8128f6266b4a03264d2a0460b7dcb3", "salt", 1000);
        this.performTest(ALGORITHM_SCRAM_SHA_256, "This is little longer password, used for testing of SCRAM digest password hashing.", "e1b96e82421b2fc57ff462eb2f001a8a436ac88f70f46267d8c171afbf55ad0f", "6e81991f001e5c568b05384d50b4159badf9f3b3e288d1e222c5a7cf599c1974", 1000);
        this.performTest(ALGORITHM_SCRAM_SHA_256, "a\u0438\u4F60\uD83C\uDCA1", "99376f7a5a7b1ff232e148a7b6d6d5c07520cb79c32cfb744b38e3458c8380bf", "\uD83C\uDCA1\u4F60\u0438a", 1000);
    }

    @Test
    public void testNormalization(){
        byte[] normalized;

        normalized = ScramDigestPasswordImpl.getNormalizedPasswordBytes("Password\uFFFF".toCharArray());
        Assert.assertArrayEquals("Password\uFFFF".getBytes(StandardCharsets.UTF_8), normalized);

        normalized = ScramDigestPasswordImpl.getNormalizedPasswordBytes("a\u0041\u030Ab".toCharArray());
        Assert.assertArrayEquals("a\u00C5b".getBytes(StandardCharsets.UTF_8), normalized);
    }

    @Test
    public void testScramDigestSHA1() throws Exception {
        this.performTest(ALGORITHM_SCRAM_SHA_1, "password".toCharArray(), "cRseQyJpnuPGn3e6d6u6JdJWk+0".toCharArray(),
                "+Z/znnNOKWUsBaCU".toCharArray(), 6400);
        this.performTest(ALGORITHM_SCRAM_SHA_1, "password".toCharArray(), "eE8dq1f1P1hZm21lfzsr3CMbiEA".toCharArray(),
                "Y0zp/R/DeO89h/De".toCharArray(), 8000);
    }

    @Test
    public void testScramDigestSHA256() throws Exception {
        this.performTest(ALGORITHM_SCRAM_SHA_256, "password".toCharArray(), "5GcjEbRaUIIci1r6NAMdI9OPZbxl9S5CFR6la9CHXYc".toCharArray(),
                "+Z/znnNOKWUsBaCU".toCharArray(), 6400);
        this.performTest(ALGORITHM_SCRAM_SHA_256, "password".toCharArray(), "NfkaDFMzn/yHr/HTv7KEFZqaONo6psRu5LBBFLEbZ+o".toCharArray(),
                "Y0zp/R/DeO89h/De".toCharArray(), 8000);
    }

    private void performTest(final String algorithm, String password, String hexDigest, String salt, final int iterationCount) throws Exception {
        performTest(algorithm, password.toCharArray(), CodePointIterator.ofString(hexDigest).hexDecode().drain(), salt.getBytes(StandardCharsets.UTF_8), iterationCount);
    }

    private void performTest(final String algorithm, char[] password, final char[] base64Digest, final char[] base64Salt, final int iterationCount) throws Exception {

        byte[] decodedDigest = CodePointIterator.ofChars(base64Digest).base64Decode(Base64Alphabet.STANDARD, false).drain();
        byte[] decodedSalt = CodePointIterator.ofChars(base64Salt).base64Decode(Base64Alphabet.STANDARD, false).drain();

        performTest(algorithm, password, decodedDigest, decodedSalt, iterationCount);
    }

    private void performTest(final String algorithm, char[] password, final byte[] decodedDigest, final byte[] decodedSalt, final int iterationCount) throws Exception {

        // use an encryptable spec to hash the password and compare the results with the expected hash.
        PasswordFactory factory = PasswordFactory.getInstance(algorithm);
        IteratedSaltedPasswordAlgorithmSpec algoSpec = new IteratedSaltedPasswordAlgorithmSpec(iterationCount, decodedSalt);
        EncryptablePasswordSpec encSpec = new EncryptablePasswordSpec(password, algoSpec);
        ScramDigestPassword scramPassword = (ScramDigestPassword) factory.generatePassword(encSpec);
        validatePassword(factory, password, scramPassword, decodedDigest, decodedSalt, iterationCount);

        // check the password -> key spec conversion.
        assertTrue("Convertable to key spec", factory.convertibleToKeySpec(scramPassword, IteratedSaltedHashPasswordSpec.class));
        IteratedSaltedHashPasswordSpec sdps = factory.getKeySpec(scramPassword, IteratedSaltedHashPasswordSpec.class);
        assertTrue("Salt correctly passed", Arrays.equals(decodedSalt, sdps.getSalt()));
        assertTrue("Iteration count correctly passed", iterationCount == sdps.getIterationCount());
        assertTrue("Digest correctly generated", Arrays.equals(decodedDigest, sdps.getHash()));

        // use the scram digest spec to build a password without hashing it (i.e., use the pre digested hash)
        sdps = new IteratedSaltedHashPasswordSpec(decodedDigest, decodedSalt, iterationCount);
        scramPassword = (ScramDigestPassword) factory.generatePassword(sdps);
        validatePassword(factory, password, scramPassword, decodedDigest, decodedSalt, iterationCount);
    }

    private void validatePassword(final PasswordFactory factory, char[] password, final ScramDigestPassword sdp,
                final byte[] decodedDigest, final byte[] decodedSalt, final int iterationCount) throws Exception {
        assertTrue("Salt correctly passed", Arrays.equals(decodedSalt, sdp.getSalt()));
        assertEquals("Iteration count correctly passed", iterationCount, sdp.getIterationCount());
        assertTrue("Digest correctly generated", Arrays.equals(decodedDigest, sdp.getDigest()));
        assertTrue("Password validation", factory.verify(sdp, password));
        assertFalse("Bad password rejection", factory.verify(sdp, "badpassword".toCharArray()));
    }

}
