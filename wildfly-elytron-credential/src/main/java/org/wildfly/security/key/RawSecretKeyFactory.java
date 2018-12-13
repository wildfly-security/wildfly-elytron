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

import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactorySpi;
import javax.crypto.spec.SecretKeySpec;

import org.jboss.logging.Logger;
import org.wildfly.security.credential._private.ElytronMessages;

/**
 * {@link SecretKeyFactorySpi} that returns the given {@link KeySpec} or {@link SecretKey} verbatim. Needed for the
 * PKCS#12 {@link KeyStore} support in CredentialStore.
 */
public final class RawSecretKeyFactory extends SecretKeyFactorySpi {

    ElytronMessages log = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security");

    @Override
    protected SecretKey engineGenerateSecret(KeySpec keySpec) throws InvalidKeySpecException {
        if (keySpec instanceof SecretKeySpec) {
            return (SecretKeySpec) keySpec;
        }

        throw log.keySpecMustBeSecretKeySpec(keySpec.getClass().getName());
    }

    @Override
    protected KeySpec engineGetKeySpec(SecretKey key, Class<?> keySpec) throws InvalidKeySpecException {
        if (SecretKeySpec.class.isAssignableFrom(keySpec) && key instanceof SecretKeySpec) {
            return (SecretKeySpec) key;
        }

        throw log.keyMustImplementSecretKeySpecAndKeySpecMustBeSecretKeySpec(
                key.getClass().getName() + ", " + keySpec.getName());
    }

    @Override
    protected SecretKey engineTranslateKey(SecretKey key) throws InvalidKeyException {
        return key;
    }
}
