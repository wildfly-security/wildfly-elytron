/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.util;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.util.concurrent.ThreadLocalRandom;

import org.junit.Test;
import org.wildfly.security.WildFlyElytronProvider;
import org.wildfly.security.password.interfaces.MaskedPassword;
import org.wildfly.security.password.spec.MaskedPasswordAlgorithmSpec;
import org.wildfly.security.password.spec.OneTimePasswordAlgorithmSpec;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

public class AbstractAlgorithmParametersSpiImplTest {

    @Test
    public void shouldRoundTripParameterSpecs() throws GeneralSecurityException, IOException {
        final OneTimePasswordAlgorithmSpec start = new OneTimePasswordAlgorithmSpec("otp-sha1",
                generateRandomOTPSeed(16), 14);

        final AlgorithmParameters oneWay = AlgorithmParameters.getInstance("otp-sha1", new WildFlyElytronProvider());
        oneWay.init(start);

        final byte[] encoded = oneWay.getEncoded();

        final AlgorithmParameters orAnother = AlgorithmParameters.getInstance("otp-sha1", new WildFlyElytronProvider());

        orAnother.init(encoded);

        final OneTimePasswordAlgorithmSpec end = orAnother.getParameterSpec(OneTimePasswordAlgorithmSpec.class);

        assertEquals(start.getAlgorithm(), end.getAlgorithm());
        assertEquals(start.getSeed(), end.getSeed());
        assertEquals(start.getSequenceNumber(), end.getSequenceNumber());
    }

    @Test
    public void maskedPasswordParameterSpecWithoutIvEncoding() throws GeneralSecurityException, IOException {
        final MaskedPasswordAlgorithmSpec start = new MaskedPasswordAlgorithmSpec("key".toCharArray(), 5, "salt".getBytes(StandardCharsets.UTF_8));

        final AlgorithmParameters oneWay = AlgorithmParameters.getInstance(MaskedPassword.ALGORITHM_MASKED_HMAC_SHA1_AES_256, new WildFlyElytronProvider());
        oneWay.init(start);

        final byte[] encoded = oneWay.getEncoded();
        assertEquals("MA4EA2tleQIBBQQEc2FsdA==", ByteIterator.ofBytes(encoded).base64Encode().drainToString()); // backward compatibility check

        final AlgorithmParameters orAnother = AlgorithmParameters.getInstance(MaskedPassword.ALGORITHM_MASKED_HMAC_SHA1_AES_256, new WildFlyElytronProvider());

        orAnother.init(encoded);

        final MaskedPasswordAlgorithmSpec end = orAnother.getParameterSpec(MaskedPasswordAlgorithmSpec.class);

        assertArrayEquals(start.getInitialKeyMaterial(), end.getInitialKeyMaterial());
        assertEquals(start.getIterationCount(), end.getIterationCount());
        assertArrayEquals(start.getSalt(), end.getSalt());
        assertArrayEquals(start.getInitializationVector(), end.getInitializationVector());
    }

    @Test
    public void maskedPasswordParameterSpecWithIvEncoding() throws GeneralSecurityException, IOException {
        final MaskedPasswordAlgorithmSpec start = new MaskedPasswordAlgorithmSpec("key".toCharArray(), 5, "salt".getBytes(StandardCharsets.UTF_8), "iv".getBytes(StandardCharsets.UTF_8));

        final AlgorithmParameters oneWay = AlgorithmParameters.getInstance(MaskedPassword.ALGORITHM_MASKED_HMAC_SHA1_AES_256, new WildFlyElytronProvider());
        oneWay.init(start);

        final byte[] encoded = oneWay.getEncoded();
        assertEquals("MBIEA2tleQIBBQQEc2FsdAQCaXY=", ByteIterator.ofBytes(encoded).base64Encode().drainToString()); // backward compatibility check

        final AlgorithmParameters orAnother = AlgorithmParameters.getInstance(MaskedPassword.ALGORITHM_MASKED_HMAC_SHA1_AES_256, new WildFlyElytronProvider());

        orAnother.init(encoded);

        final MaskedPasswordAlgorithmSpec end = orAnother.getParameterSpec(MaskedPasswordAlgorithmSpec.class);

        assertArrayEquals(start.getInitialKeyMaterial(), end.getInitialKeyMaterial());
        assertEquals(start.getIterationCount(), end.getIterationCount());
        assertArrayEquals(start.getSalt(), end.getSalt());
        assertArrayEquals(start.getInitializationVector(), end.getInitializationVector());
    }

    /**
     * This method generates a valid random seed using only valid characters
     * from ISO-646 Invariant Code.
     *
     * @param saltSize number of bytes to be generated
     *
     * @return The seed
     */
    private String generateRandomOTPSeed(int saltSize){
        byte[] salt = new byte[saltSize];
        for (int i = 0, len = salt.length; i < len; )
            for (int rnd = ThreadLocalRandom.current().nextInt(0, 128),
                 n = Math.min(len - i, Integer.SIZE/Byte.SIZE);
                 n-- > 0; rnd >>= Byte.SIZE) {
                salt[i++] = (byte)rnd;
            }

        return new String(salt, StandardCharsets.US_ASCII);
    }
}
