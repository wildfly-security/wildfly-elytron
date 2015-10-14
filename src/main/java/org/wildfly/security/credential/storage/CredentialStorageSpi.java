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

import org.wildfly.security.credential.Credential;

import java.util.Map;
import java.util.Set;

/**
 * SPI for credential storage provider to implement.
 *
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>
 */
public abstract class CredentialStorageSpi {

    /**
     * Field indicating successful initialization ({@link #initialize(Map)}. Each subclass should set this field.
     */
    protected boolean initialized = false;

    /**
     * Construct a new instance of this SPI.
     */
    protected CredentialStorageSpi() {
    }

    /**
     * Initialize credential storage service with given attributes. This procedure should set {@link #initialized} after
     * successful initialization.
     *
     * @param attributes attributes to used to pass information to credential storage service
     * @throws StorageException if initialization fails due to any reason
     */
    public abstract void initialize(Map<String, String> attributes) throws StorageException;

    /**
     * Checks whether underlying credential storage service is initialized.
     *
     * @return {@code true} in case of initialization passed successfully, {@code false} otherwise.
     */

    public boolean isInitialized() {
        return initialized;
    }

    /**
     * Check if credential storage service supports modification of its storage
     * @return {@code true} in case of modification of the storage is supported, {@code false} otherwise
     */
    public abstract boolean isModifiable();

    /**
     * Check whether credential storage service has an entry associated with the given credential alias of specified credential type.
     * @param credentialAlias key to check existence
     * @param credentialType to check existence in the credential storage
     * @param <C> the class of type to which should be credential casted
     * @return {@code true} in case key exist in storage otherwise {@code false}
     * @throws StorageException when there is a problem with credential storage
     * @throws UnsupportedCredentialTypeException when the credentialType is not supported
     */
    public abstract <C extends Credential> boolean exists(String credentialAlias, Class<C> credentialType)
            throws StorageException, UnsupportedCredentialTypeException;

    /**
     * Store credential to the storage service under the given alias. If given alias already contains specific credential type type the credential
     * replaces older one. <em>Note:</em> {@link CredentialStorageSpi} supports storing of multiple entries (credential types) per alias.
     * Each must be of different credential type.
     * @param credentialAlias to store the credential to the storage
     * @param credentialType - credential type to be stored under the credentialAlias to the storage
     * @param credential instance of {@link Credential} to store
     * @throws StorageException when the credential cannot be stored.
     * @throws UnsupportedCredentialTypeException when the credentialType is not supported
     */
    public abstract  <C extends Credential> void store(String credentialAlias, Class<C> credentialType, C credential)
            throws StorageException, UnsupportedCredentialTypeException;

    /**
     * Retrieve credential stored in the storage under the key and of the credential type
     * @param credentialAlias to find the credential in the storage
     * @param credentialType - credential type to retrieve from under the credentialAlias from the storage
     * @param <C> the class of type to which should be credential casted
     * @return instance of {@link Credential} stored in the storage
     * @throws StorageException - if credentialAlias credentialType combination doesn't exist or credentialAlias cannot be retrieved
     * @throws UnsupportedCredentialTypeException when the credentialType is not supported
     */
    public abstract <C extends Credential> C retrieve(String credentialAlias, Class<C> credentialType)
            throws StorageException, UnsupportedCredentialTypeException;

    /**
     * Remove the credentialType with from given alias from the credential storage service.
     * @param credentialAlias alias to remove
     * @param credentialType - credential type to be removed from under the credentialAlias from the credential storage service
     * @param <C> the type of credential which will be removed
     * @throws StorageException - if credentialAlias credentialType combination doesn't exist or credentialAlias cannot be removed
     * @throws UnsupportedCredentialTypeException when the credentialType is not supported
     */
    public abstract <C extends Credential> void remove(String credentialAlias, Class<C> credentialType)
            throws StorageException, UnsupportedCredentialTypeException;

    /**
     * Returns credential aliases stored in this storage as {@code Set<String>}.
     *
     * It is not mandatory to override this method (throws {@link UnsupportedOperationException} by default).
     *
     * @return {@code Set<String>} of all keys stored in this storage
     * @throws UnsupportedOperationException when this method is not supported by the underlying credential store
     * @throws StorageException if there is any problem with internal storage
     */
    public Set<String> getAliases() throws UnsupportedOperationException, StorageException {
        throw new UnsupportedOperationException();
    }

}
