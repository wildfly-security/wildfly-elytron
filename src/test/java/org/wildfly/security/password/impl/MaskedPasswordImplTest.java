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

import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.stream.Collectors;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;
import org.wildfly.security.password.interfaces.MaskedPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;

import static org.junit.Assert.assertTrue;

@RunWith(Parameterized.class)
public class MaskedPasswordImplTest {

    @Parameter
    public String algorithm;

    @Parameters(name = "{index}: {0}")
    public static Iterable<Object[]> algorithms() {
        return Arrays.stream(MaskedPassword.class.getDeclaredFields())
                .filter(f -> f.getName().startsWith("ALGORITHM_MASKED_")).map(f -> {
                    try {
                        return new Object[] {f.get(null)};
                    } catch (final IllegalAccessException e) {
                        throw new RuntimeException(e);
                    }
                }).collect(Collectors.toList());
    }

    @Test
    public void shouldSupportAlgorithms() throws InvalidKeySpecException {
        final char[] secret = "my deep dark secret".toCharArray();

        final MaskedPasswordImpl maskedPassword = new MaskedPasswordImpl(algorithm, secret);

        final MaskedPasswordImpl unmaskedPassword = new MaskedPasswordImpl(maskedPassword);
        final ClearPasswordSpec clearPasswordSpec = unmaskedPassword.getKeySpec(ClearPasswordSpec.class);

        final char[] unmasked = clearPasswordSpec.getEncodedPassword();
        assertTrue("Masked and unmasked secrets differ: " + new String(secret) + " vs " + new String(unmasked),
                Arrays.equals(secret, unmasked));
    }

}
