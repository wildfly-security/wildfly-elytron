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

import java.security.spec.AlgorithmParameterSpec;

import org.wildfly.common.Assert;
import org.wildfly.security.key.KeyUtil;

import javax.crypto.SecretKey;

/**
 * A secret key credential.
 */
public final class SecretKeyCredential implements AlgorithmCredential {
    private final SecretKey secretKey;

    /**
     * Construct a new instance.
     *
     * @param secretKey the secret key (may not be {@code null})
     */
    public SecretKeyCredential(final SecretKey secretKey) {
        Assert.checkNotNullParam("secretKey", secretKey);
        this.secretKey = secretKey;
    }

    /**
     * Get the secret key.
     *
     * @return the secret key (not {@code null})
     */
    public SecretKey getSecretKey() {
        return secretKey;
    }

    public boolean supportsParameters(final Class<? extends AlgorithmParameterSpec> paramSpecClass) {
        return KeyUtil.getParameters(secretKey, paramSpecClass) != null;
    }

    public <P extends AlgorithmParameterSpec> P getParameters(final Class<P> paramSpecClass) {
        return KeyUtil.getParameters(secretKey, paramSpecClass);
    }

    public boolean impliesSameParameters(final Credential other) {
        return KeyUtil.hasParameters(secretKey, other.getParameters(AlgorithmParameterSpec.class));
    }

    public String getAlgorithm() {
        return secretKey.getAlgorithm();
    }

    public SecretKeyCredential clone() {
        final SecretKey secretKey = this.secretKey;
        final SecretKey clone = KeyUtil.cloneKey(SecretKey.class, secretKey);
        return clone == secretKey ? this : new SecretKeyCredential(clone);
    }

}
