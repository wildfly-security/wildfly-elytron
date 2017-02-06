/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2017 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.key;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;

import javax.crypto.spec.SecretKeySpec;

import org.junit.Test;

import static org.hamcrest.core.IsSame.sameInstance;
import static org.junit.Assert.assertThat;

public class RawSecretKeyFactoryTest {

    static final byte[] KEY_BYTES = "some key".getBytes();

    RawSecretKeyFactory rawFactory = new RawSecretKeyFactory();

    SecretKeySpec keySpec = new SecretKeySpec(KEY_BYTES, "DES");

    @Test(expected = InvalidKeySpecException.class)
    public void shouldComplainAboutNotGivenASecretKey() throws GeneralSecurityException {
        rawFactory.engineGetKeySpec(keySpec, RSAPrivateKeySpec.class);
    }

    @Test(expected = InvalidKeySpecException.class)
    public void shouldComplainAboutNotGivenASecretKeySpec() throws InvalidKeySpecException {
        rawFactory.engineGenerateSecret(new RSAPrivateKeySpec(BigInteger.ONE, BigInteger.ONE));
    }

    @Test
    public void shouldGenerateSecretKeyFromSecretKeySpec() throws InvalidKeySpecException {
        assertThat(rawFactory.engineGenerateSecret(keySpec), sameInstance(keySpec));
    }

    @Test
    public void shouldGenerateSecretKeySpecFromSecretKey() throws GeneralSecurityException {
        assertThat(rawFactory.engineGetKeySpec(keySpec, SecretKeySpec.class), sameInstance(keySpec));
    }
}
