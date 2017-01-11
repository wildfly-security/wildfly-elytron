/*
 * JBoss, Home of Professional Open Source
 * Copyright 2015 Red Hat, Inc., and individual contributors
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

import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

import org.junit.Test;
import org.wildfly.security.password.interfaces.MaskedPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.password.spec.IteratedSaltedPasswordAlgorithmSpec;
import org.wildfly.security.password.spec.MaskedPasswordSpec;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class MaskedPasswordImplPicketBoxCompatibilityTest {

    final char[] initialKey = "somearbitrarycrazystringthatdoesnotmatter".toCharArray();

    final String picketBoxAlgorithm = MaskedPassword.ALGORITHM_MASKED_MD5_DES;

    final int picketBoxIterationCount = 50;

    final byte[] picketBoxMaskedPasswordBytes = new byte[] {-23, -52, 73, 36, -27, -114, 50, -81};

    final byte[] picketBoxSalt = "Mxyzptlk".getBytes();

    final String secret = "vault13";

    @Test
    public void shouldBeCompatibleWithPicketBoxMaskedPasswords() throws InvalidKeySpecException {
        final MaskedPasswordImpl picketBoxMaskedPassword = new MaskedPasswordImpl(picketBoxAlgorithm,
                new MaskedPasswordSpec(initialKey, picketBoxIterationCount, picketBoxSalt,
                        picketBoxMaskedPasswordBytes));

        final ClearPasswordSpec clearPasswordSpec = picketBoxMaskedPassword.getKeySpec(ClearPasswordSpec.class);

        assertEquals("Masked password should unmask PicketBox masked password", secret,
                new String(clearPasswordSpec.getEncodedPassword()));
    }

    @Test
    public void shouldGenerateMaskedPasswordsAsInPicketbox() throws InvalidKeySpecException {
        final MaskedPasswordImpl maskedPassword = new MaskedPasswordImpl(picketBoxAlgorithm, secret.toCharArray(),
                new IteratedSaltedPasswordAlgorithmSpec(picketBoxIterationCount, picketBoxSalt));

        final byte[] encoded = maskedPassword.getMaskedPasswordBytes();

        assertTrue("Password masking should generate same values as PicketBox",
                Arrays.equals(picketBoxMaskedPasswordBytes, encoded));
    }
}
