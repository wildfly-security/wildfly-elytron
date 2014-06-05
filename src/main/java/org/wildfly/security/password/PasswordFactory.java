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
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

/**
 * A factory for passwords.
 * <p>
 * Password factories are used to handle and manipulate <em>password</em> objects and their corresponding
 * <em>password specifications</em>.  Passwords are a kind of key which are used to store and compare against a
 * string of text entered by a human.  Passwords can be one-way ({@link OneWayPassword}) or two-way
 * ({@link TwoWayPassword}).
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class PasswordFactory {
    private final Provider provider;
    private final String algorithm;
    private final PasswordFactorySpi spi;

    private PasswordFactory(final Provider provider, final String algorithm, final PasswordFactorySpi spi) {
        this.provider = provider;
        this.algorithm = algorithm;
        this.spi = spi;
    }

    /**
     * Get a password factory instance.  The returned password factory object will implement the given algorithm.
     *
     * @param algorithm the name of the algorithm
     * @return a password factory instance
     * @throws NoSuchAlgorithmException if the given algorithm has no available implementations
     */
    public static PasswordFactory getInstance(String algorithm) throws NoSuchAlgorithmException {
        for (Provider provider : Security.getProviders()) {
            final Provider.Service service = provider.getService("PasswordFactory", algorithm);
            if (service != null) {
                return new PasswordFactory(provider, algorithm, (PasswordFactorySpi) service.newInstance(null));
            }
        }
        return null;
    }

    /**
     * Get a password factory instance.  The returned password factory object will implement the given algorithm.
     *
     * @param algorithm the name of the algorithm
     * @param providerName the name of the provider to use
     * @return a password factory instance
     * @throws NoSuchAlgorithmException if the given algorithm has no available implementations
     */
    public static PasswordFactory getInstance(String algorithm, String providerName) throws NoSuchAlgorithmException, NoSuchProviderException {
        final Provider provider = Security.getProvider(providerName);
        if (provider == null) throw new NoSuchProviderException(providerName);
        return getInstance(algorithm, provider);
    }

    /**
     * Get a password factory instance.  The returned password factory object will implement the given algorithm.
     *
     * @param algorithm the name of the algorithm
     * @param provider the provider to use
     * @return a password factory instance
     * @throws NoSuchAlgorithmException if the given algorithm has no available implementations
     */
    public static PasswordFactory getInstance(String algorithm, Provider provider) throws NoSuchAlgorithmException {
        final Provider.Service service = provider.getService("PasswordFactory", algorithm);
        if (service == null) throw new NoSuchAlgorithmException(algorithm);
        return new PasswordFactory(provider, algorithm, (PasswordFactorySpi) service.newInstance(null));
    }

    /**
     * Get the provider of this password factory.
     *
     * @return the provider
     */
    public Provider getProvider() {
        return provider;
    }

    /**
     * Get the algorithm of this password factory.
     *
     * @return the algorithm
     */
    public String getAlgorithm() {
        return algorithm;
    }

    /**
     * Generate a new {@link Password} object for the given specification.
     *
     * @param keySpec the specification
     * @return the password object
     * @throws InvalidKeySpecException if the key specification is not valid for this algorithm
     */
    public Password generatePassword(KeySpec keySpec) throws InvalidKeySpecException {
        return spi.engineGeneratePassword(algorithm, keySpec);
    }

    /**
     * Generate a key specification of the given type from the given password object.
     *
     * @param password the password object
     * @param specType the specification class
     * @param <T> the specification type
     * @return the key specification
     * @throws InvalidKeySpecException if the password cannot be translated to the given key specification type
     */
    public <T extends KeySpec> T getKeySpec(Password password, Class<T> specType) throws InvalidKeySpecException {
        return spi.engineGetKeySpec(algorithm, password, specType);
    }

    /**
     * Determine whether the given password can be converted to the given key specification type by this factory.
     *
     * @param password the password object
     * @param specType the specification class
     * @param <T> the specification type
     * @return {@code true} if the password can be converted, {@code false} otherwise
     */
    public <T extends KeySpec> boolean convertibleToKeySpec(Password password, Class<T> specType) {
        return spi.engineConvertibleToKeySpec(algorithm, password, specType);
    }

    /**
     * Translate the given password object to one which is consumable by this factory.
     *
     * @param password the password object
     * @return the equivalent password object that this factory can work with
     * @throws InvalidKeyException if the given password is not supported by this algorithm
     */
    public Password translate(Password password) throws InvalidKeyException {
        return spi.engineTranslatePassword(algorithm, password);
    }

    /**
     * Verify a password guess.
     *
     * @param password the password object
     * @param guess the guessed password characters
     * @return {@code true} if the guess matches the password, {@code false} otherwise
     * @throws InvalidKeyException if the given password is not supported by this factory
     */
    public boolean verify(Password password, char[] guess) throws InvalidKeyException {
        return spi.engineVerify(algorithm, password, guess);
    }
}
