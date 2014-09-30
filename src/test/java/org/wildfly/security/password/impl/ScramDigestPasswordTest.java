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
import static org.wildfly.security.password.interfaces.ScramDigestPassword.*;

import java.security.Provider;
import java.security.Security;
import java.util.Arrays;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.interfaces.ScramDigestPassword;
import org.wildfly.security.password.spec.EncryptablePasswordSpec;
import org.wildfly.security.password.spec.HashedPasswordAlgorithmSpec;
import org.wildfly.security.password.spec.ScramDigestPasswordSpec;
import org.wildfly.security.util.Base64;

/**
 * <p>
 * Tests for the SCRAM password implementation. The Base64-encoded digests and salts used in the tests were generated
 * by the Python Passlib scram hash function.
 * </p>
 *
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 */

public class ScramDigestPasswordTest {

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
    public void testScramDigestSHA1() throws Exception {
        this.performTest(ALGORITHM_SCRAM_SHA_1, "cRseQyJpnuPGn3e6d6u6JdJWk+0".toCharArray(),
                "+Z/znnNOKWUsBaCU".toCharArray(), 6400);
        this.performTest(ALGORITHM_SCRAM_SHA_1, "eE8dq1f1P1hZm21lfzsr3CMbiEA".toCharArray(),
                "Y0zp/R/DeO89h/De".toCharArray(), 8000);
    }

    @Test
    public void testScramDigestSHA256() throws Exception {
        this.performTest(ALGORITHM_SCRAM_SHA_256, "5GcjEbRaUIIci1r6NAMdI9OPZbxl9S5CFR6la9CHXYc".toCharArray(),
                "+Z/znnNOKWUsBaCU".toCharArray(), 6400);
        this.performTest(ALGORITHM_SCRAM_SHA_256, "NfkaDFMzn/yHr/HTv7KEFZqaONo6psRu5LBBFLEbZ+o".toCharArray(),
                "Y0zp/R/DeO89h/De".toCharArray(), 8000);
    }

    private void performTest(final String algorithm, final char[] base64Digest, final char[] base64Salt, final int iterationCount) throws Exception {

        byte[] decodedDigest = Base64.base64DecodeStandard(base64Digest, 0);
        byte[] decodedSalt = Base64.base64DecodeStandard(base64Salt, 0);

        // use an encryptable spec to hash the password and compare the results with the expected hash.
        PasswordFactory factory = PasswordFactory.getInstance(algorithm);
        HashedPasswordAlgorithmSpec algoSpec = new HashedPasswordAlgorithmSpec(iterationCount, decodedSalt);
        EncryptablePasswordSpec encSpec = new EncryptablePasswordSpec(password, algoSpec);
        ScramDigestPassword scramPassword = (ScramDigestPassword) factory.generatePassword(encSpec);
        validatePassword(factory, scramPassword, decodedDigest, decodedSalt, iterationCount);

        // check the password -> key spec conversion.
        assertTrue("Convertable to key spec", factory.convertibleToKeySpec(scramPassword, ScramDigestPasswordSpec.class));
        ScramDigestPasswordSpec sdps = factory.getKeySpec(scramPassword, ScramDigestPasswordSpec.class);
        assertTrue("Salt correctly passed", Arrays.equals(decodedSalt, sdps.getSalt()));
        assertTrue("Iteration count correctly passed", iterationCount == sdps.getIterationCount());
        assertTrue("Digest correctly generated", Arrays.equals(decodedDigest, sdps.getDigest()));

        // use the scram digest spec to build a password without hashing it (i.e., use the pre digested hash)
        sdps = new ScramDigestPasswordSpec(algorithm, decodedDigest, decodedSalt, iterationCount);
        scramPassword = (ScramDigestPassword) factory.generatePassword(sdps);
        validatePassword(factory, scramPassword, decodedDigest, decodedSalt, iterationCount);
    }

    private void validatePassword(final PasswordFactory factory, final ScramDigestPassword sdp, final byte[] decodedDigest,
                                  final byte[] decodedSalt, final int iterationCount) throws Exception {
        assertTrue("Salt correctly passed", Arrays.equals(decodedSalt, sdp.getSalt()));
        assertTrue("Iteration count correctly passed", iterationCount == sdp.getIterationCount());
        assertTrue("Digest correctly generated", Arrays.equals(decodedDigest, sdp.getDigest()));
        assertTrue("Password validation", factory.verify(sdp, password));
        assertFalse("Bad password rejection", factory.verify(sdp, "badpassword".toCharArray()));
    }
}
