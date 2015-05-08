/*
 * JBoss, Home of Professional Open Source.
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

package org.wildfly.security.password;

import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

/**
 * The SPI for password factories to implement.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public abstract class PasswordFactorySpi {

    /**
     * Construct a new instance.
     */
    protected PasswordFactorySpi() {
    }

    /**
     * Generate a password from the given key specification.
     *
     * @param algorithm the password algorithm
     * @param keySpec the key specification
     * @return the password
     * @throws InvalidKeySpecException if the key specification is not supported
     */
    protected abstract Password engineGeneratePassword(String algorithm, KeySpec keySpec) throws InvalidKeySpecException;

    /**
     * Get a key specification for the given password object.
     *
     * @param algorithm the password algorithm
     * @param password the password object
     * @param keySpecType the key specification class
     * @param <S> the key specification type
     * @return the key specification
     * @throws InvalidKeySpecException if the key specification type is not supported
     */
    protected abstract <S extends KeySpec> S engineGetKeySpec(String algorithm, Password password, Class<S> keySpecType) throws InvalidKeySpecException;

    /**
     * Determine whether the given password can be translated into one which is consumable by this factory.  If this
     * method returns {@code true}, then {@link #engineTranslatePassword(String, Password)} must succeed.
     *
     * @param password the password object
     * @return {@code true} if the given password is supported by this algorithm, {@code false} otherwise
     */
    protected abstract boolean engineIsTranslatablePassword(final String algorithm, final Password password);

    /**
     * Translate a password object into one which is supported by this engine.
     *
     * @param algorithm the password algorithm
     * @param password the password object
     * @return the translated password
     * @throws InvalidKeyException if the given password type is not supported
     */
    protected abstract Password engineTranslatePassword(String algorithm, Password password) throws InvalidKeyException;

    /**
     * Perform password verification.
     *
     * @param algorithm the password algorithm
     * @param password the password object
     * @param guess the guessed password
     * @return {@code true} if the password matches, {@code false} otherwise
     * @throws InvalidKeyException if the given password type is not supported
     */
    protected abstract boolean engineVerifyCredential(String algorithm, Password password, final Object guess) throws InvalidKeyException;

    /**
     * Determine whether the given password object is convertible to the given key specification type.
     *
     * @param algorithm the password algorithm
     * @param password the password object
     * @param keySpecType the key specification class
     * @param <S> the key specification type
     * @return {@code true} if the password is convertible, {@code false} otherwise
     */
    protected abstract <S extends KeySpec> boolean engineConvertibleToKeySpec(String algorithm, Password password, Class<S> keySpecType);
}
