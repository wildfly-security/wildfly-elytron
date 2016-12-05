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

import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;

import org.wildfly.common.Assert;
import org.wildfly.security.key.KeyUtil;

/**
 * A public key credential.
 */
public final class PublicKeyCredential implements AlgorithmCredential {
    private final PublicKey publicKey;

    /**
     * Construct a new instance.
     *
     * @param publicKey the public key (may not be {@code null})
     */
    public PublicKeyCredential(final PublicKey publicKey) {
        Assert.checkNotNullParam("publicKey", publicKey);
        this.publicKey = publicKey;
    }

    /**
     * Get the public key.
     *
     * @return the public key (not {@code null})
     */
    public PublicKey getPublicKey() {
        return publicKey;
    }

    public boolean supportsParameters(final Class<? extends AlgorithmParameterSpec> paramSpecClass) {
        return KeyUtil.getParameters(publicKey, paramSpecClass) != null;
    }

    public <P extends AlgorithmParameterSpec> P getParameters(final Class<P> paramSpecClass) {
        return KeyUtil.getParameters(publicKey, paramSpecClass);
    }

    public boolean impliesSameParameters(final AlgorithmCredential other) {
        return KeyUtil.hasParameters(publicKey, other.getParameters());
    }

    /**
     * Get the public key algorithm.
     *
     * @return the public key algorithm name
     */
    public String getAlgorithm() {
        return publicKey.getAlgorithm();
    }

    public PublicKeyCredential clone() {
        return this;
    }

}
