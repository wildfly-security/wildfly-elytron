/*
 * JBoss, Home of Professional Open Source
 * Copyright 2018 Red Hat, Inc., and individual contributors
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
import static org.junit.Assert.assertTrue;

import java.security.Provider;
import java.security.Security;
import java.security.spec.KeySpec;
import java.util.Arrays;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.wildfly.security.WildFlyElytronProvider;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.interfaces.MaskedPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.password.spec.EncryptablePasswordSpec;
import org.wildfly.security.password.spec.IteratedSaltedPasswordAlgorithmSpec;
import org.wildfly.security.password.spec.MaskedPasswordSpec;

/*
 * @author Jan Kalina <jkalina@redhat.com>
 * @author Zoran Regvart <zregvart@redhat.com>
 */
public class MaskedPasswordPicketBoxCompatibilityTest {

    private final char[] initialKey = "somearbitrarycrazystringthatdoesnotmatter".toCharArray();

    private final String picketBoxAlgorithm = MaskedPassword.ALGORITHM_MASKED_MD5_DES;

    private final int picketBoxIterationCount = 50;

    private final byte[] picketBoxMaskedPasswordBytes = new byte[] {-23, -52, 73, 36, -27, -114, 50, -81};

    private final byte[] picketBoxSalt = "Mxyzptlk".getBytes();

    private final String secret = "vault13";

    private static final Provider provider = new WildFlyElytronProvider();

    @BeforeClass
    public static void setup() {
        Security.addProvider(provider);
    }

    @AfterClass
    public static void removeProvider() {
        Security.removeProvider(provider.getName());
    }

    @Test
    public void shouldBeCompatibleWithPicketBoxMaskedPasswords() throws Exception {
        PasswordFactory factory = PasswordFactory.getInstance(picketBoxAlgorithm);

        KeySpec maskedSpec = new MaskedPasswordSpec(initialKey, picketBoxIterationCount, picketBoxSalt, picketBoxMaskedPasswordBytes);
        MaskedPassword picketBoxMaskedPassword = (MaskedPassword) factory.generatePassword(maskedSpec);

        ClearPasswordSpec clearPasswordSpec = factory.getKeySpec(picketBoxMaskedPassword, ClearPasswordSpec.class);

        assertEquals("Masked password should unmask PicketBox masked password", secret,
                new String(clearPasswordSpec.getEncodedPassword()));
    }

    @Test
    public void shouldGenerateMaskedPasswordsAsInPicketbox() throws Exception {
        PasswordFactory factory = PasswordFactory.getInstance(picketBoxAlgorithm);

        KeySpec passwordSpec = new EncryptablePasswordSpec(secret.toCharArray(),
                new IteratedSaltedPasswordAlgorithmSpec(picketBoxIterationCount, picketBoxSalt));
        MaskedPassword maskedPassword = (MaskedPassword) factory.generatePassword(passwordSpec);

        byte[] encoded = maskedPassword.getMaskedPasswordBytes();

        assertTrue("Password masking should generate same values as PicketBox",
                Arrays.equals(picketBoxMaskedPasswordBytes, encoded));
    }
}