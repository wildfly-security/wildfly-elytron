/*
 * JBoss, Home of Professional Open Source
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
package org.wildfly.security.credential.external;

import org.wildfly.common.Assert;
import org.wildfly.security.credential.Credential;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;
import java.util.Map;
import java.util.Set;

/**
 * External credential.
 * It is source for credentials obtained from external source.
 *
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>
 */
public class ExternalCredential {

    /**
     * JCA service type for a external credential provider.
     */
    public static final String EXTERNAL_CREDENTIAL_PROVIDER_TYPE = "ExternalCredential";

    private final Provider provider;
    private final String type;
    private final ExternalCredentialSpi spi;

    /**
     * Constructor of ExternalCredential.
     *
     * @param provider JCA provider
     * @param spi Service Provider Interface implementation
     * @param type of Service Provider
     */
    private ExternalCredential(Provider provider, ExternalCredentialSpi spi, String type) {
        Assert.assertNotNull(provider);
        Assert.assertNotNull(spi);
        Assert.assertNotNull(type);
        this.provider = provider;
        this.type = type;
        this.spi = spi;
    }

    /**
     * Get a {@code ExternalCredential} instance. The returned CredentialStore object will implement the given way
     * of getting credential.
     *
     * @param way the name of the way to get the credential
     * @return a {@code CredentialStore} instance
     * @throws NoSuchAlgorithmException if the given way has no available implementations
     */
    public static ExternalCredential getInstance(String way) throws NoSuchAlgorithmException {
        return getInstance(way, null);
    }

    /**
     * Get a {@code ExternalCredential} instance. The returned CredentialStore object will implement the given way
     * of getting credential.
     *
     * @param way the name of the way to get the credential
     * @param nameSpace a base on which instance parameter names will be used (could be {@code null})
     * @return a {@code CredentialStore} instance
     * @throws NoSuchAlgorithmException if the given way has no available implementations
     */
    public static ExternalCredential getInstance(String way, String nameSpace) throws NoSuchAlgorithmException {
        for (Provider provider : Security.getProviders()) {
            final Provider.Service service = provider.getService(EXTERNAL_CREDENTIAL_PROVIDER_TYPE, way);
            if (service != null) {
                return new ExternalCredential(provider, (ExternalCredentialSpi) service.newInstance(nameSpace), way);
            }
        }
        throw new NoSuchAlgorithmException();
    }

    /**
     * Get a {@code ExternalCredential} instance.  The returned CredentialStore object will implement the given way
     * of getting credential.
     *
     * @param way the name of the way to get the credential
     * @param nameSpace a base on which instance parameter names will be used (could be {@code null})
     * @param providerName the name of the provider to use
     * @return a {@code CredentialStore} instance
     * @throws NoSuchAlgorithmException if the given way has no available implementations
     * @throws NoSuchProviderException if given provider name cannot match any registered {@link Provider}
     */
    public static ExternalCredential getInstance(String way, String nameSpace, String providerName) throws NoSuchAlgorithmException, NoSuchProviderException {
        final Provider provider = Security.getProvider(providerName);
        if (provider == null) throw new NoSuchProviderException(providerName);
        return getInstance(way, nameSpace, provider);
    }

    /**
     * Get a {@code ExternalCredential} instance.  The returned CredentialStore object will implement the given way
     * of getting credential.
     *
     * @param way the name of the way to get the credential
     * @param nameSpace a base on which instance parameter names will be used (could be {@code null})
     * @param provider the provider to use
     * @return a {@code CredentialStore} instance
     * @throws NoSuchAlgorithmException if the given way has no available implementations
     */
    public static ExternalCredential getInstance(String way, String nameSpace, Provider provider) throws NoSuchAlgorithmException {
        final Provider.Service service = provider.getService(EXTERNAL_CREDENTIAL_PROVIDER_TYPE, way);
        if (service == null) throw new NoSuchAlgorithmException(way);
        return new ExternalCredential(provider, (ExternalCredentialSpi) service.newInstance(nameSpace), way);
    }

    /**
     * Returns {@link Provider} which provides {@link ExternalCredentialSpi} for this instance.
     * @return {@link Provider} of this {@link ExternalCredentialSpi}
     */
    public Provider getProvider() {
        return provider;
    }

    /**
     * Returns JCA service type of {@link ExternalCredentialSpi} for this instance.
     * @return type of service of this {@link ExternalCredentialSpi}
     */
    public String getType() {
        return type;
    }


    /**
     * Resolve credential from external source using specified parameters.
     * @param parameters to obtain external password
     * @param credentialType type of {@link Credential} to get back form this method
     * @param <C> type parameter of {@link Credential}
     * @return {@link Credential} from service provider
     * @throws ExternalCredentialException if anything goes wrong while resolving the credential
     */
    public <C extends Credential> C resolveCredential(Map<String, String> parameters, Class<C> credentialType)
            throws ExternalCredentialException {
        return spi.resolveCredential(parameters, credentialType);
    }

    /**
     * Resolve credential from external source using password command.
     * @param passwordCommand to obtain external password
     * @param credentialType type of {@link Credential} to get back form this method
     * @param <C> type parameter of {@link Credential}
     * @return {@link Credential} from service provider
     * @throws ExternalCredentialException if anything goes wrong while resolving the credential
     */
    public <C extends Credential> C resolveCredential(String passwordCommand, Class<C> credentialType)
            throws ExternalCredentialException {
        return spi.resolveCredential(passwordCommand, credentialType);
    }

    /**
     * This method provides parameters supported by external credential provider. The {@code Set} can be used
     * to filter parameters supplied {@link #resolveCredential(Map, Class)} or {@link #resolveCredential(String, Class)}
     * methods.
     *
     * @return {@code Set<String>} of supported parameters
     */
    public Set<String> supportedParameters() {
        return spi.supportedParameters();
    }

}
