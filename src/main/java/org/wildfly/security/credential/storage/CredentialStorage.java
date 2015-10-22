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
package org.wildfly.security.credential.storage;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;
import java.util.Map;
import java.util.Set;

import org.wildfly.security.credential.Credential;

/**
 * This class represents credential storage functionality.
 * Type of the credential storage is determined by instance type and is loaded from {@link java.security.Provider}.
 *
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>.
 */
public class CredentialStorage {

    /**
     * JCA service type for a credential storage.
     */
    public static final String CREDENTIAL_STORAGE_TYPE = "CredentialStorage";

    private final Provider provider;
    private final String type;
    private final CredentialStorageSpi spi;

    /**
     * Get a {@code CredentialStorage} instance.  The returned CredentialStorage object will implement the given algorithm.
     *
     * @param algorithm the name of the algorithm
     * @return a {@code CredentialStorage} instance
     * @throws NoSuchAlgorithmException if the given algorithm has no available implementations
     */
    public static CredentialStorage getInstance(String algorithm) throws NoSuchAlgorithmException {
        for (Provider provider : Security.getProviders()) {
            final Provider.Service service = provider.getService(CREDENTIAL_STORAGE_TYPE, algorithm);
            if (service != null) {
                return new CredentialStorage(provider, (CredentialStorageSpi) service.newInstance(null), algorithm);
            }
        }
        throw new NoSuchAlgorithmException();
    }

    /**
     * Get a {@code CredentialStorage} instance.  The returned CredentialStorage object will implement the given algorithm.
     *
     * @param algorithm the name of the algorithm
     * @param providerName the name of the provider to use
     * @return a {@code CredentialStorage} instance
     * @throws NoSuchAlgorithmException if the given algorithm has no available implementations
     * @throws NoSuchProviderException if given provider name cannot match any registered {@link Provider}
     */
    public static CredentialStorage getInstance(String algorithm, String providerName) throws NoSuchAlgorithmException, NoSuchProviderException {
        final Provider provider = Security.getProvider(providerName);
        if (provider == null) throw new NoSuchProviderException(providerName);
        return getInstance(algorithm, provider);
    }

    /**
     * Get a {@code CredentialStorage} instance.  The returned CredentialStorage object will implement the given algorithm.
     *
     * @param algorithm the name of the algorithm
     * @param provider the provider to use
     * @return a {@code CredentialStorage} instance
     * @throws NoSuchAlgorithmException if the given algorithm has no available implementations
     */
    public static CredentialStorage getInstance(String algorithm, Provider provider) throws NoSuchAlgorithmException {
        final Provider.Service service = provider.getService(CREDENTIAL_STORAGE_TYPE, algorithm);
        if (service == null) throw new NoSuchAlgorithmException(algorithm);
        return new CredentialStorage(provider, (CredentialStorageSpi) service.newInstance(null), algorithm);
    }

    /**
     * Constructor to create CredentialStorage instance
     * @param provider {@link Provider} of {@link CredentialStorageSpi} instance
     * @param spi {@link CredentialStorageSpi} instance
     * @param type JCA type of CredentialStorage
     */
    protected CredentialStorage(Provider provider, CredentialStorageSpi spi, String type) {
        this.provider = provider;
        this.spi = spi;
        this.type = type;
    }

    /**
     * Initialize Credential Storage service with given attributes.
     * This procedure should set {@link CredentialStorageSpi#initialized} after successful initialization.
     *
     * @param attributes attributes to used to pass information to Credential Storage service
     * @throws StorageException if initialization fails due to any reason
     */
    public void initialize(Map<String, String> attributes) throws StorageException {
        spi.initialize(attributes);
    }

    /**
     * Checks whether underlying credential storage is initialized.
     * @return {@code true} in case of initialization passed successfully, {@code false} otherwise.
     */
    public boolean isInitialized() {
        return spi.isInitialized();
    }

    /**
     * Check if credential storage supports modification of actual storage
     * @return true in case of modification of storage is supported
     */
    public boolean isModifiable() {
        return spi.isModifiable();
    }

    /**
     * Check whether credential storage has an entry associated with the given credential alias of specified credential type.
     * @param credentialAlias alias to check existence
     * @param credentialType to check existence in the credential storage
     * @param <C> the class of type to which should be credential casted
     * @return true in case key exist in storage
     * @throws StorageException when there is a problem with credential storage
     * @throws UnsupportedCredentialTypeException when the credentialType is not supported
     */
    public <C extends Credential> boolean exists(String credentialAlias, Class<C> credentialType) throws StorageException, UnsupportedCredentialTypeException {
        return spi.exists(credentialAlias, credentialType);
    }

    /**
     * Store credential to the storage under the given alias. If given alias already contains specific credential type type the credential
     * replaces older one. <em>Note:</em> {@link CredentialStorageSpi} supports storing of multiple entries (credential types) per alias.
     * Each must be of different credential type.
     * @param credentialAlias to store the credential to the storage
     * @param credential instance of {@link Credential} to store
     * @param <C> the class of type to which should be credential casted
     * @throws StorageException when the credential cannot be stored
     * @throws UnsupportedCredentialTypeException when the credentialType is not supported
     */
    public <C extends Credential> void store(String credentialAlias, C credential) throws StorageException, UnsupportedCredentialTypeException {
        spi.store(credentialAlias, credential);
    }

    /**
     * Retrieve credential stored in the storage under the key and of the credential type
     * @param credentialAlias to find the credential in the storage
     * @param credentialType - credential type to retrieve from under the credentialAlias from the storage
     * @param <C> the class of type to which should be credential casted
     * @return instance of {@link Credential} stored in the storage
     * @throws StorageException - if credentialAlias credentialType combination doesn't exist or credentialAlias cannot be retrieved
     * @throws UnsupportedCredentialTypeException when the credentialType is not supported
     */
    public <C extends Credential> C retrieve(String credentialAlias, Class<C> credentialType) throws StorageException, UnsupportedCredentialTypeException {
        return spi.retrieve(credentialAlias, credentialType);
    }

    /**
     * Remove the credentialType with from given alias from the storage.
     * @param credentialAlias alias to remove
     * @param credentialType - credential type to be removed from under the credentialAlias from the storage
     * @param <C> the type of credential which will be removed
     * @throws StorageException - if credentialAlias credentialType combination doesn't exist or credentialAlias cannot be removed
     * @throws UnsupportedCredentialTypeException when the credentialType is not supported
     */
    public <C extends Credential> void remove(String credentialAlias, Class<C> credentialType) throws StorageException, UnsupportedCredentialTypeException {
        spi.remove(credentialAlias, credentialType);
    }

    /**
     * Returns {@code Set<String>} stored in this storage.
     *
     * @return {@code Set<String>} of all keys stored in this storage
     * @throws UnsupportedOperationException when this method is not supported by the underlying credential store
     * @throws StorageException if there is any problem with internal storage
     */
    public Set<String> getAliases() throws UnsupportedOperationException, StorageException {
        return spi.getAliases();
    }

    /**
     * Returns {@link Provider} which provides {@link CredentialStorageSpi} for this instance.
     * @return {@link Provider} of this {@link CredentialStorageSpi}
     */
    public Provider getProvider() {
        return provider;
    }

    /**
     * Returns JCA service type of {@link CredentialStorageSpi} for this instance.
     * @return type of service of this {@link CredentialStorageSpi}
     */
    public String getType() {
        return type;
    }
}
