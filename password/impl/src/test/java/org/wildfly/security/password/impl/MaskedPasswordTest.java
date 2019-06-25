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

import java.security.Provider;
import java.security.Security;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.stream.Collectors;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;
import org.wildfly.security.WildFlyElytronProvider;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.interfaces.MaskedPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.password.spec.EncryptablePasswordSpec;
import org.wildfly.security.password.spec.MaskedPasswordAlgorithmSpec;
import org.wildfly.security.password.spec.MaskedPasswordSpec;
import org.wildfly.security.password.util.ModularCrypt;

/**
 * @author Jan Kalina <jkalina@redhat.com>
 * @author Zoran Regvart <zregvart@redhat.com>
 */
@RunWith(Parameterized.class)
public class MaskedPasswordTest {

    private static final Provider provider = new WildFlyElytronProvider();

    @BeforeClass
    public static void setup() {
        Security.setProperty("crypto.policy", "unlimited");
        Security.addProvider(provider);
    }

    @AfterClass
    public static void removeProvider() {
        Security.removeProvider(provider.getName());
    }

    @Parameter
    public String algorithm;

    @Parameters(name = "{index}: {0}")
    public static Iterable<Object[]> algorithms() {
        return Arrays.stream(MaskedPassword.class.getDeclaredFields())
                .filter(f -> f.getName().startsWith("ALGORITHM_MASKED_") && !f.isAnnotationPresent(Deprecated.class)).map(f -> {
                    try {
                        return new Object[] {f.get(null)};
                    } catch (final IllegalAccessException e) {
                        throw new RuntimeException(e);
                    }
                }).collect(Collectors.toList());
    }

    @Test
    public void testClearSpec() throws Exception {
        ClearPasswordSpec clearSpec = new ClearPasswordSpec("myMaskedPassword".toCharArray());
        PasswordFactory factory = PasswordFactory.getInstance(algorithm);
        MaskedPassword masked = (MaskedPassword) factory.generatePassword(clearSpec);

        ClearPasswordSpec unmasked = factory.getKeySpec(masked, ClearPasswordSpec.class);
        Assert.assertEquals("myMaskedPassword", new String(unmasked.getEncodedPassword()));

        KeySpec maskedSpec = new MaskedPasswordSpec(masked.getInitialKeyMaterial(), masked.getIterationCount(), masked.getSalt(), masked.getMaskedPasswordBytes(), masked.getInitializationVector());
        MaskedPassword copyOfMasked = (MaskedPassword) factory.generatePassword(maskedSpec);

        ClearPasswordSpec unmasked2 = factory.getKeySpec(copyOfMasked, ClearPasswordSpec.class);
        Assert.assertEquals("myMaskedPassword", new String(unmasked2.getEncodedPassword()));
    }

    @Test
    public void testEncryptableSpec() throws Exception {
        char[] initialKeyMaterial = "my deep dark secret".toCharArray();

        MaskedPasswordAlgorithmSpec algorithmSpec = new MaskedPasswordAlgorithmSpec(initialKeyMaterial, 1, new byte[8]);

        EncryptablePasswordSpec spec = new EncryptablePasswordSpec("myMaskedPassword".toCharArray(), algorithmSpec);
        PasswordFactory factory = PasswordFactory.getInstance(algorithm);
        MaskedPassword maskedPassword = (MaskedPassword) factory.generatePassword(spec);

        char[] encoded = ModularCrypt.encode(maskedPassword);
        System.out.println(encoded);
        Password decoded = ModularCrypt.decode(encoded);

        Password translated = factory.translate(decoded);
        ClearPasswordSpec unmasked = factory.getKeySpec(translated, ClearPasswordSpec.class);
        Assert.assertEquals("myMaskedPassword", new String(unmasked.getEncodedPassword()));
    }
}
