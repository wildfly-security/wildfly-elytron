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
import java.util.List;

import sun.security.jca.ProviderList;
import sun.security.jca.Providers;

/**
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

    public static PasswordFactory getInstance(String algorithm) throws NoSuchAlgorithmException {
        for (Provider provider : Security.getProviders()) {
            final Provider.Service service = provider.getService("PasswordFactory", algorithm);
            if (service != null) {
                return new PasswordFactory(provider, algorithm, (PasswordFactorySpi) service.newInstance(null));
            }
        }
        ProviderList list = Providers.getProviderList();
        final List<Provider.Service> services = list.getServices("PasswordFactory", algorithm);
        for (Provider.Service service : services) {
            service.newInstance(null);
        }
        return null;
    }

    public static PasswordFactory getInstance(String algorithm, String providerName) throws NoSuchAlgorithmException, NoSuchProviderException {
        final Provider provider = Security.getProvider(providerName);
        if (provider == null) throw new NoSuchProviderException(providerName);
        return getInstance(algorithm, provider);
    }

    public static PasswordFactory getInstance(String algorithm, Provider provider) throws NoSuchAlgorithmException {
        final Provider.Service service = provider.getService("PasswordFactory", algorithm);
        if (service == null) throw new NoSuchAlgorithmException(algorithm);
        return new PasswordFactory(provider, algorithm, (PasswordFactorySpi) service.newInstance(null));
    }

    public Provider getProvider() {
        return provider;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public Password generatePassword(KeySpec keySpec) throws InvalidKeySpecException {
        return spi.engineGeneratePassword(keySpec);
    }

    public <T extends KeySpec> T getKeySpec(Password password, Class<T> specType) throws InvalidKeySpecException {
        return spi.engineGetKeySpec(password, specType);
    }

    public <T extends KeySpec> boolean convertibleToKeySpec(Password password, Class<T> specType) {
        return spi.engineConvertibleToKeySpec(password, specType);
    }

    public Password translate(Password password) throws InvalidKeyException {
        return spi.engineTranslatePassword(password);
    }

    public boolean verify(Password password, char[] guess) throws InvalidKeyException {
        return spi.engineVerify(password, guess);
    }
}
