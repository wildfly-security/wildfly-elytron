/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2021 Red Hat, Inc., and individual contributors
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

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.WildFlyElytronPasswordProvider;
import org.wildfly.security.password.interfaces.OneTimePassword;
import org.wildfly.security.password.spec.EncryptablePasswordSpec;
import org.wildfly.security.password.spec.OneTimePasswordAlgorithmSpec;

import java.security.Provider;
import java.security.Security;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

public class OneTimePasswordTest {

    private static final Provider provider = WildFlyElytronPasswordProvider.getInstance();

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
        String password = "test_password";
        String seed = "ke1234";
        int sequenceNumber = 500;

        PasswordFactory passwordFactory = PasswordFactory.getInstance(OneTimePassword.ALGORITHM_OTP_SHA_512);
        OneTimePasswordAlgorithmSpec oneTimeAlgorithmSpec = new OneTimePasswordAlgorithmSpec(OneTimePassword.ALGORITHM_OTP_SHA_512, seed, sequenceNumber);
        EncryptablePasswordSpec encryptableSpec = new EncryptablePasswordSpec(password.toCharArray(), oneTimeAlgorithmSpec);
        OneTimePassword oneTimePassword = (OneTimePassword) passwordFactory.generatePassword(encryptableSpec);

        assertEquals("Seed correctly passed", seed, oneTimePassword.getSeed());
        assertEquals("Sequence number correctly passed", sequenceNumber, oneTimePassword.getSequenceNumber());
    }

    @Test
    public void testTranslateFunctionality() throws Exception {
        String password = "test_password";
        String seed = "ke1234";
        int sequenceNumber = 500;
        int updatedSequenceNumber = 600;

        OneTimePasswordAlgorithmSpec oneTimeAlgorithmSpec = new OneTimePasswordAlgorithmSpec(OneTimePassword.ALGORITHM_OTP_SHA_512, seed, sequenceNumber);
        OneTimePasswordAlgorithmSpec updatedSequenceOneTimeAlgorithmSpec = new OneTimePasswordAlgorithmSpec(OneTimePassword.ALGORITHM_OTP_SHA_512, seed, updatedSequenceNumber);

        PasswordFactory passwordFactory = PasswordFactory.getInstance(OneTimePassword.ALGORITHM_OTP_SHA_512);

        EncryptablePasswordSpec encryptableSpec = new EncryptablePasswordSpec(password.toCharArray(), oneTimeAlgorithmSpec);
        OneTimePassword oneTimePassword = (OneTimePassword) passwordFactory.generatePassword(encryptableSpec);

        assertEquals("Seed correctly passed", seed, oneTimePassword.getSeed());
        assertEquals("Sequence number correctly passed", sequenceNumber, oneTimePassword.getSequenceNumber());

        encryptableSpec = new EncryptablePasswordSpec(password.toCharArray(), updatedSequenceOneTimeAlgorithmSpec);
        OneTimePassword oneTimePasswordUpdatedSequence = (OneTimePassword) passwordFactory.generatePassword(encryptableSpec);
        OneTimePassword oneTimePasswordTranslated = (OneTimePassword) passwordFactory.transform(oneTimePassword, updatedSequenceOneTimeAlgorithmSpec);

        assertArrayEquals("Hashes should be same", oneTimePasswordUpdatedSequence.getHash(), oneTimePasswordTranslated.getHash());
    }
}
