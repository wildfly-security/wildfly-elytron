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
package org.wildfly.security.storage;

import org.wildfly.security.password.Password;

import java.util.Map;


/**
 * SPI for password storage to implement.
 *
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>.
 */
public abstract class PasswordStorageSpi {

    /**
     * Field indicating successful initialization ({@link #initialize(Map)}. Each subclass should set this field.
     */
    protected boolean initialized = false;


    /**
     * Construct a new instance of this SPI.
     */
    protected PasswordStorageSpi() {
    }


    /**
     * Check whether given key has an entry associated with.
     * @param key key to check existence
     * @param passwordClass password class to check existence
     * @param <T> {@link Password} class
     * @return true in case key exist in storage
     * @throws StorageException when there is a problem with passwordClass cannot be stored.
     * @throws UnsupportedPasswordClassException when the passwordClass is not supported
     */
    public abstract <T extends Password> boolean exists(String key, Class<T> passwordClass) throws StorageException, UnsupportedPasswordClassException;

    /**
     * Store password to the storage under the key. If given key already contains specific Password type the password
     * replaces older one. <em>Note:</em> {@link PasswordStorageSpi} supports storing of multiple entries per key. Each
     * must be of different Password type.
     * @param key key to store password with
     * @param passwordClass password class to use to store the password
     * @param password instance of {@link Password} to store
     * @throws StorageException when the password cannot be stored.
     * @throws UnsupportedPasswordClassException when the passwordClass is not supported
     */
    public abstract <T extends Password> void store(String key, Class<T> passwordClass, Password password) throws StorageException, UnsupportedPasswordClassException;

    /**
     * Retrieve password stored in the storage under the key and of the passwordClass
     * @param key key to find password
     * @param passwordClass password class to retrieve from storage
     * @param <T> {@link Password} class
     * @return instance of {@link Password} stored in the storage
     * @throws StorageException if key passwordClass combination doesn't exist
     * @throws UnsupportedPasswordClassException - when the passwordClass is not supported
     */
    public abstract <T extends Password> T retrieve(String key, Class<T> passwordClass) throws StorageException, UnsupportedPasswordClassException;

    /**
     * Remove the passwordClass instance under the key from the storage.
     * @param key key to use for removal
     * @param passwordClass password class to remove from the key
     * @param <T> {@link Password} class
     * @throws StorageException if key passwordClass combination doesn't exist or key cannot be removed
     * @throws UnsupportedPasswordClassException - when the passwordClass is not supported
     */
    public abstract <T extends Password> void remove(String key, Class<T> passwordClass) throws StorageException, UnsupportedPasswordClassException;

    /**
     * Initialize Password Storage service with given attributes.
     * This procedure should set {@link #initialized} after successful initialization.
     *
     * @param attributes attributes to used to pass information to Password Storage service
     * @throws StorageException if initialization fails due to any reason
     */
    public abstract void initialize(Map<String, String> attributes) throws StorageException;

    /**
     * Checks whether underlying Password Storage is initialized.
     * @return {@code true} in case of initialization passed successfully, {@code false} otherwise.
     */
    public boolean isInitialized() {
        return initialized;
    }
}
