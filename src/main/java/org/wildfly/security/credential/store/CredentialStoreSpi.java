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

import java.security.spec.AlgorithmParameterSpec;
import java.util.Map;
import java.util.Set;

import org.wildfly.security.credential.Credential;

/**
 * SPI for credential store provider to implement.
 *
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>
 */
public abstract class CredentialStoreSpi {

    /**
     * Field indicating successful initialization ({@link #initialize(Map, CredentialStore.ProtectionParameter)}. Each subclass should set this field.
     */
    protected boolean initialized = false;

    /**
     * Construct a new instance of this SPI.
     */
    protected CredentialStoreSpi() {
    }

    /**
     * Initialize credential store service with given attributes. This procedure should set {@link #initialized} after
     * successful initialization.
     *
     * @param attributes attributes to used to pass information to credential store service
     * @param protectionParameter the store-wide protection parameter to apply, or {@code null} for none
     * @throws CredentialStoreException if initialization fails due to any reason
     */
    public abstract void initialize(Map<String, String> attributes, CredentialStore.ProtectionParameter protectionParameter) throws CredentialStoreException;

    /**
     * Checks whether underlying credential store service is initialized.
     *
     * @return {@code true} in case of initialization passed successfully, {@code false} otherwise.
     */

    public boolean isInitialized() {
        return initialized;
    }

    /**
     * Check if credential store service supports modification of its store
     * @return {@code true} in case of modification of the store is supported, {@code false} otherwise
     */
    public abstract boolean isModifiable();

    /**
     * Check whether credential store service has an entry associated with the given credential alias of specified
     * credential type.  The default implementation simply attempts to retrieve the credential without a protection
     * parameter, and returns {@code true} if any credential was returned.  Credential stores which use a protection
     * parameter should override this method.
     *
     * @param credentialAlias key to check existence
     * @param credentialType to class of credential to look for
     * @return {@code true} in case key exist in store otherwise {@code false}
     * @throws CredentialStoreException when there is a problem with credential store
     */
    public boolean exists(String credentialAlias, Class<? extends Credential> credentialType) throws CredentialStoreException {
        return retrieve(credentialAlias, credentialType, null, null, null) != null;
    }

    /**
     * Store credential to the credential store service under the given alias. If given alias already contains specific credential type type the credential
     * replaces older one. <em>Note:</em> {@link CredentialStoreSpi} supports storing of multiple entries (credential types) per alias.
     * Each must be of different credential type, or differing algorithm, or differing parameters.
     *
     * @param credentialAlias to store the credential to the store
     * @param credential instance of {@link Credential} to store
     * @param protectionParameter the protection parameter to apply to the entry, or {@code null} for none
     * @throws CredentialStoreException when the credential cannot be stored
     * @throws UnsupportedCredentialTypeException when the credentialType is not supported
     */
    public abstract void store(String credentialAlias, Credential credential, CredentialStore.ProtectionParameter protectionParameter)
            throws CredentialStoreException, UnsupportedCredentialTypeException;

    /**
     * Retrieve the credential stored in the store under the given alias, matching the given criteria.
     *
     * @param credentialAlias to find the credential in the store
     * @param credentialType the credential type class (must not be {@code null})
     * @param credentialAlgorithm the credential algorithm to match, or {@code null} to match any algorithm
     * @param parameterSpec the parameter specification to match, or {@code null} to match any parameters
     * @param protectionParameter the protection parameter to use to access the entry, or {@code null} for none
     * @param <C> the credential type
     * @return instance of {@link Credential} stored in the store, or {@code null} if the credential is not found
     * @throws CredentialStoreException if the credential cannot be retrieved due to an error
     */
    public abstract <C extends Credential> C retrieve(String credentialAlias, Class<C> credentialType, String credentialAlgorithm, AlgorithmParameterSpec parameterSpec, CredentialStore.ProtectionParameter protectionParameter) throws CredentialStoreException;

    /**
     * Remove the credentialType with from given alias from the credential store service.
     *
     * @param credentialAlias alias to remove
     * @param credentialType the credential type class to match (must not be {@code null})
     * @param credentialAlgorithm the credential algorithm to match, or {@code null} to match all algorithms
     * @param parameterSpec the credential parameters to match, or {@code null} to match all parameters
     * @throws CredentialStoreException if the credential cannot be removed due to an error
     */
    public abstract void remove(String credentialAlias, Class<? extends Credential> credentialType, String credentialAlgorithm, AlgorithmParameterSpec parameterSpec) throws CredentialStoreException;

    /**
     * Returns credential aliases stored in this store as {@code Set<String>}.
     *
     * It is not mandatory to override this method (throws {@link UnsupportedOperationException} by default).
     *
     * @return {@code Set<String>} of all keys stored in this store
     * @throws UnsupportedOperationException when this method is not supported by the underlying credential store
     * @throws CredentialStoreException if there is any problem with internal store
     */
    public Set<String> getAliases() throws UnsupportedOperationException, CredentialStoreException {
        throw new UnsupportedOperationException();
    }
}
