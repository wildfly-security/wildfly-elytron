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

import org.wildfly.security.credential.Credential;

import java.util.Map;
import java.util.Set;

/**
 * SPI for credential store provider to implement.
 *
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>
 */
public abstract class CredentialStoreSpi {

    /**
     * Field indicating successful initialization ({@link #initialize(Map)}. Each subclass should set this field.
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
     * @throws CredentialStoreException if initialization fails due to any reason
     */
    public abstract void initialize(Map<String, String> attributes) throws CredentialStoreException;

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
     * Check whether credential store service has an entry associated with the given credential alias of specified credential type.
     * @param credentialAlias key to check existence
     * @param credentialType to check existence in the credential store
     * @param <C> the class of type to which should be credential casted
     * @return {@code true} in case key exist in store otherwise {@code false}
     * @throws CredentialStoreException when there is a problem with credential store
     * @throws UnsupportedCredentialTypeException when the credentialType is not supported
     */
    public abstract <C extends Credential> boolean exists(String credentialAlias, Class<C> credentialType)
            throws CredentialStoreException, UnsupportedCredentialTypeException;

    /**
     * Store credential to the credential store service under the given alias. If given alias already contains specific credential type type the credential
     * replaces older one. <em>Note:</em> {@link CredentialStoreSpi} supports storing of multiple entries (credential types) per alias.
     * Each must be of different credential type.
     * @param credentialAlias to store the credential to the store
     * @param credential instance of {@link Credential} to store
     * @throws CredentialStoreException when the credential cannot be stored.
     * @throws UnsupportedCredentialTypeException when the credentialType is not supported
     */
    public abstract  <C extends Credential> void store(String credentialAlias, C credential)
            throws CredentialStoreException, UnsupportedCredentialTypeException;

    /**
     * Retrieve credential stored in the store under the key and of the credential type
     * @param credentialAlias to find the credential in the store
     * @param credentialType - credential type to retrieve from under the credentialAlias from the store
     * @param <C> the class of type to which should be credential casted
     * @return instance of {@link Credential} stored in the store
     * @throws CredentialStoreException - if credentialAlias credentialType combination doesn't exist or credentialAlias cannot be retrieved
     * @throws UnsupportedCredentialTypeException when the credentialType is not supported
     */
    public abstract <C extends Credential> C retrieve(String credentialAlias, Class<C> credentialType)
            throws CredentialStoreException, UnsupportedCredentialTypeException;

    /**
     * Remove the credentialType with from given alias from the credential store service.
     * @param credentialAlias alias to remove
     * @param credentialType - credential type to be removed from under the credentialAlias from the credential store service
     * @param <C> the type of credential which will be removed
     * @throws CredentialStoreException - if credentialAlias credentialType combination doesn't exist or credentialAlias cannot be removed
     * @throws UnsupportedCredentialTypeException when the credentialType is not supported
     */
    public abstract <C extends Credential> void remove(String credentialAlias, Class<C> credentialType)
            throws CredentialStoreException, UnsupportedCredentialTypeException;

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
