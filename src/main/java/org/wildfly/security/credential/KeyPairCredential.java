/*
 * JBoss, Home of Professional Open Source.
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

package org.wildfly.security.credential;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;

import org.wildfly.common.Assert;
import org.wildfly.security._private.ElytronMessages;
import org.wildfly.security.key.KeyUtil;

/**
 * A public/private key pair credential.
 */
public final class KeyPairCredential implements AlgorithmCredential {
    private final KeyPair keyPair;

    /**
     * Construct a new instance.
     *
     * @param keyPair the key pair (may not be {@code null})
     */
    public KeyPairCredential(final KeyPair keyPair) {
        Assert.checkNotNullParam("keyPair", keyPair);
        final PublicKey publicKey = keyPair.getPublic();
        if (publicKey == null) {
            throw ElytronMessages.log.publicKeyIsNull();
        }
        final PrivateKey privateKey = keyPair.getPrivate();
        if (privateKey == null) {
            throw ElytronMessages.log.privateKeyIsNull();
        }
        if (! publicKey.getAlgorithm().equals(privateKey.getAlgorithm())) {
            throw ElytronMessages.log.mismatchedPublicPrivateKeyAlgorithms();
        }
        if (! KeyUtil.hasSameParameters(publicKey, privateKey)) {
            throw ElytronMessages.log.mismatchedPublicPrivateKeyParameters();
        }
        this.keyPair = keyPair;
    }

    /**
     * Get the key pair.
     *
     * @return the key pair (not {@code null})
     */
    public KeyPair getKeyPair() {
        return keyPair;
    }

    public boolean supportsParameters(final Class<? extends AlgorithmParameterSpec> paramSpecClass) {
        return KeyUtil.getParameters(keyPair.getPublic(), paramSpecClass) != null;
    }

    public <P extends AlgorithmParameterSpec> P getParameters(final Class<P> paramSpecClass) {
        return KeyUtil.getParameters(keyPair.getPublic(), paramSpecClass);
    }

    public boolean impliesSameParameters(final Credential other) {
        return KeyUtil.hasParameters(keyPair.getPublic(), other.getParameters(AlgorithmParameterSpec.class));
    }

    public String getAlgorithm() {
        return keyPair.getPublic().getAlgorithm();
    }

    public KeyPairCredential clone() {
        final PrivateKey privateKey = keyPair.getPrivate();
        final PrivateKey clone = KeyUtil.cloneKey(PrivateKey.class, privateKey);
        return privateKey == clone ? this : new KeyPairCredential(new KeyPair(keyPair.getPublic(), clone));
    }
}
