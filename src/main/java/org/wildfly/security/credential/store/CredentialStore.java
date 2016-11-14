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
package org.wildfly.security.credential.store;

import static org.wildfly.security._private.ElytronMessages.log;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;
import java.util.Map;
import java.util.Set;

import org.wildfly.security.credential.Credential;

/**
 * This class represents credential store functionality.
 * Type of the credential store is determined by instance type and is loaded from {@link java.security.Provider}.
 *
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>.
 */
public class CredentialStore {

    /**
     * JCA service type for a credential store.
     */
    public static final String CREDENTIAL_STORE_TYPE = "CredentialStore";

    private final Provider provider;
    private final String type;
    private final CredentialStoreSpi spi;

    /**
     * Get a {@code CredentialStore} instance.  The returned CredentialStore object will implement the given algorithm.
     *
     * @param algorithm the name of the algorithm
     * @return a {@code CredentialStore} instance
     * @throws NoSuchAlgorithmException if the given algorithm has no available implementations
     */
    public static CredentialStore getInstance(String algorithm) throws NoSuchAlgorithmException {
        for (Provider provider : Security.getProviders()) {
            final Provider.Service service = provider.getService(CREDENTIAL_STORE_TYPE, algorithm);
            if (service != null) {
                return new CredentialStore(provider, (CredentialStoreSpi) service.newInstance(null), algorithm);
            }
        }
        throw new NoSuchAlgorithmException();
    }

    /**
     * Get a {@code CredentialStore} instance.  The returned CredentialStore object will implement the given algorithm.
     *
     * @param algorithm the name of the algorithm
     * @param providerName the name of the provider to use
     * @return a {@code CredentialStore} instance
     * @throws NoSuchAlgorithmException if the given algorithm has no available implementations
     * @throws NoSuchProviderException if given provider name cannot match any registered {@link Provider}
     */
    public static CredentialStore getInstance(String algorithm, String providerName) throws NoSuchAlgorithmException, NoSuchProviderException {
        final Provider provider = Security.getProvider(providerName);
        if (provider == null) throw new NoSuchProviderException(providerName);
        return getInstance(algorithm, provider);
    }

    /**
     * Get a {@code CredentialStore} instance.  The returned CredentialStore object will implement the given algorithm.
     *
     * @param algorithm the name of the algorithm
     * @param provider the provider to use
     * @return a {@code CredentialStore} instance
     * @throws NoSuchAlgorithmException if the given algorithm has no available implementations
     */
    public static CredentialStore getInstance(String algorithm, Provider provider) throws NoSuchAlgorithmException {
        final Provider.Service service = provider.getService(CREDENTIAL_STORE_TYPE, algorithm);
        if (service == null) throw new NoSuchAlgorithmException(algorithm);
        return new CredentialStore(provider, (CredentialStoreSpi) service.newInstance(null), algorithm);
    }

    /**
     * Constructor to create CredentialStore instance
     * @param provider {@link Provider} of {@link CredentialStoreSpi} instance
     * @param spi {@link CredentialStoreSpi} instance
     * @param type JCA type of CredentialStore
     */
    protected CredentialStore(Provider provider, CredentialStoreSpi spi, String type) {
        this.provider = provider;
        this.spi = spi;
        this.type = type;
    }

    /**
     * Initialize Credential Store service with given attributes.
     * This procedure should set {@link CredentialStoreSpi#initialized} after successful initialization.
     *
     * @param attributes attributes to used to pass information to Credential Store service
     * @throws CredentialStoreException if initialization fails due to any reason
     */
    public void initialize(Map<String, String> attributes) throws CredentialStoreException {
        spi.initialize(attributes);
    }

    /**
     * Checks whether underlying credential store is initialized.
     * @return {@code true} in case of initialization passed successfully, {@code false} otherwise.
     */
    public boolean isInitialized() {
        return spi.isInitialized();
    }

    /**
     * Check if credential store supports modification of actual store
     * @return true in case of modification of store is supported
     */
    public boolean isModifiable() {
        return spi.isModifiable();
    }

    /**
     * Check whether credential store has an entry associated with the given credential alias of specified credential type.
     * @param credentialAlias alias to check existence
     * @param credentialType to check existence in the credential store
     * @param <C> the class of type to which should be credential casted
     * @return true in case key exist in store
     * @throws CredentialStoreException when there is a problem with credential store
     * @throws UnsupportedCredentialTypeException when the credentialType is not supported
     */
    public <C extends Credential> boolean exists(String credentialAlias, Class<C> credentialType) throws CredentialStoreException, UnsupportedCredentialTypeException {
        return spi.exists(credentialAlias, credentialType);
    }

    /**
     * Store credential to the store under the given alias. If given alias already contains specific credential type type the credential
     * replaces older one. <em>Note:</em> {@link CredentialStoreSpi} supports storing of multiple entries (credential types) per alias.
     * Each must be of different credential type.
     * @param credentialAlias to store the credential to the store
     * @param credential instance of {@link Credential} to store
     * @param <C> the class of type to which should be credential casted
     * @throws CredentialStoreException when the credential cannot be stored
     * @throws UnsupportedCredentialTypeException when the credentialType is not supported
     */
    public <C extends Credential> void store(String credentialAlias, C credential) throws CredentialStoreException, UnsupportedCredentialTypeException {
        if (isModifiable()) {
            spi.store(credentialAlias, credential);
        } else {
            throw log.nonModifiableCredentialStore("store");
        }
    }

    /**
     * Retrieve credential stored in the store under the key and of the credential type
     * @param credentialAlias to find the credential in the store
     * @param credentialType - credential type to retrieve from under the credentialAlias from the store
     * @param <C> the class of type to which should be credential casted
     * @return instance of {@link Credential} stored in the store
     * @throws CredentialStoreException - if credentialAlias credentialType combination doesn't exist or credentialAlias cannot be retrieved
     * @throws UnsupportedCredentialTypeException when the credentialType is not supported
     */
    public <C extends Credential> C retrieve(String credentialAlias, Class<C> credentialType) throws CredentialStoreException, UnsupportedCredentialTypeException {
        return spi.retrieve(credentialAlias, credentialType);
    }

    /**
     * Remove the credentialType with from given alias from the store.
     * @param credentialAlias alias to remove
     * @param credentialType - credential type to be removed from under the credentialAlias from the store
     * @param <C> the type of credential which will be removed
     * @throws CredentialStoreException - if credentialAlias credentialType combination doesn't exist or credentialAlias cannot be removed
     * @throws UnsupportedCredentialTypeException when the credentialType is not supported
     */
    public <C extends Credential> void remove(String credentialAlias, Class<C> credentialType) throws CredentialStoreException, UnsupportedCredentialTypeException {
        if (isModifiable()) {
            spi.remove(credentialAlias, credentialType);
        } else {
            throw log.nonModifiableCredentialStore("remove");
        }
    }

    /**
     * Returns {@code Set<String>} stored in this store.
     *
     * @return {@code Set<String>} of all keys stored in this store
     * @throws UnsupportedOperationException when this method is not supported by the underlying credential store
     * @throws CredentialStoreException if there is any problem with internal store
     */
    public Set<String> getAliases() throws UnsupportedOperationException, CredentialStoreException {
        return spi.getAliases();
    }

    /**
     * Returns {@link Provider} which provides {@link CredentialStoreSpi} for this instance.
     * @return {@link Provider} of this {@link CredentialStoreSpi}
     */
    public Provider getProvider() {
        return provider;
    }

    /**
     * Returns JCA service type of {@link CredentialStoreSpi} for this instance.
     * @return type of service of this {@link CredentialStoreSpi}
     */
    public String getType() {
        return type;
    }
}
