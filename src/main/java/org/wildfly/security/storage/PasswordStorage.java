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

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;
import java.util.Map;
import java.util.Set;

/**
 * This class represents Password Storage functionality.
 * Type of the Password Storage is determined by instance type and is loaded from {@link java.security.Provider}.
 *
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>.
 */
public class PasswordStorage {

    /**
     * JCA service type for Password Storage.
     */
    public static final String PASSWORD_STORAGE_TYPE = "PasswordStorage";
    /**
     * Value of this option denotes file which is used as vault storage.
     */
    public static final String NAME = "elytron.name";
    /**
     * Value of this option denotes file which is used as vault storage.
     */
    public static final String STORAGE_FILE = "elytron.storage.file";
    /**
     * Value of this option is storage password. Could be omitted but {@code CALLBACK} has to specified.
     */
    public static final String STORAGE_PASSWORD = "storage.password";

    /**
     * Option name to denote base of all files used by {@link PasswordStorageSpi} implementor.
     * It can be used to pass this value using {@link #initialize(Map)} method to the engine class.
     * Useful for using relative name(s) of storage file(s) in the engine. It is completely optional to implement
     * but useful when your engine is used inside something bigger (e.g. WildFly Server) to have location for
     * password storage defined.
     */
    public static final String FILE_BASE = "elytron.file.base";

    private final Provider provider;
    private final String type;
    private final PasswordStorageSpi spi;

    /**
     * Get a {@code PasswordStorage} instance.  The returned PasswordStorage object will implement the given algorithm.
     *
     * @param algorithm the name of the algorithm
     * @return a {@code PasswordStorage} instance
     * @throws NoSuchAlgorithmException if the given algorithm has no available implementations
     */
    public static PasswordStorage getInstance(String algorithm) throws NoSuchAlgorithmException {
        for (Provider provider : Security.getProviders()) {
            final Provider.Service service = provider.getService(PASSWORD_STORAGE_TYPE, algorithm);
            if (service != null) {
                return new PasswordStorage(provider, (PasswordStorageSpi) service.newInstance(null), algorithm);
            }
        }
        throw new NoSuchAlgorithmException();
    }

    /**
     * Get a {@code PasswordStorage} instance.  The returned PasswordStorage object will implement the given algorithm.
     *
     * @param algorithm the name of the algorithm
     * @param providerName the name of the provider to use
     * @return a {@code PasswordStorage} instance
     * @throws NoSuchAlgorithmException if the given algorithm has no available implementations
     * @throws NoSuchProviderException if given provider name cannot match any registered {@link Provider}
     */
    public static PasswordStorage getInstance(String algorithm, String providerName) throws NoSuchAlgorithmException, NoSuchProviderException {
        final Provider provider = Security.getProvider(providerName);
        if (provider == null) throw new NoSuchProviderException(providerName);
        return getInstance(algorithm, provider);
    }

    /**
     * Get a {@code PasswordStorage} instance.  The returned PasswordStorage object will implement the given algorithm.
     *
     * @param algorithm the name of the algorithm
     * @param provider the provider to use
     * @return a {@code PasswordStorage} instance
     * @throws NoSuchAlgorithmException if the given algorithm has no available implementations
     */
    public static PasswordStorage getInstance(String algorithm, Provider provider) throws NoSuchAlgorithmException {
        final Provider.Service service = provider.getService(PASSWORD_STORAGE_TYPE, algorithm);
        if (service == null) throw new NoSuchAlgorithmException(algorithm);
        return new PasswordStorage(provider, (PasswordStorageSpi) service.newInstance(null), algorithm);
    }

    /**
     * Constructor to create PasswordStorage instance
     * @param provider {@link Provider} of {@link PasswordStorageSpi} instance
     * @param spi {@link PasswordStorageSpi} instance
     * @param type JCA type of PasswordStorage
     */
    protected PasswordStorage(Provider provider, PasswordStorageSpi spi, String type) {
        this.provider = provider;
        this.spi = spi;
        this.type = type;
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
    public <T extends Password> boolean exists(String key, Class<T> passwordClass) throws StorageException, UnsupportedPasswordClassException {
        return spi.exists(key, passwordClass);
    }

    /**
     * Remove the passwordClass instance under the key from the storage.
     * @param key - key to use for removal
     * @param passwordClass - password class to remove from the key
     * @param <T> - {@link Password} class
     * @throws StorageException - if key passwordClass combination doesn't exist or key cannot be removed
     * @throws UnsupportedPasswordClassException - when the passwordClass is not supported
     */
    public <T extends Password> void remove(String key, Class<T> passwordClass) throws StorageException, UnsupportedPasswordClassException {
        spi.remove(key, passwordClass);
    }

    /**
     * Initialize Password Storage service with given attributes.
     * This procedure should set {@link PasswordStorageSpi#initialized} after successful initialization.
     *
     * @param attributes attributes to used to pass information to Password Storage service
     * @throws StorageException if initialization fails due to any reason
     */
    public void initialize(Map<String, String> attributes) throws StorageException {
        spi.initialize(attributes);
    }

    /**
     * Retrieve password stored in the storage under the key and of the passwordClass
     * @param key key to find password
     * @param passwordClass password class to retrieve from storage
     * @param <T> {@link Password} class
     * @return instance of {@link Password} stored in the storage
     * @throws StorageException if key passwordClass combination doesn't exist
     * @throws UnsupportedPasswordClassException - when the passwordClass is not supported
     */
    public <T extends Password> T retrieve(String key, Class<T> passwordClass) throws StorageException, UnsupportedPasswordClassException {
        return spi.retrieve(key, passwordClass);
    }

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
    public<T extends Password> void store(String key, Class<T> passwordClass, T password) throws StorageException, UnsupportedPasswordClassException {
        spi.store(key, passwordClass, password);
    }

    /**
     * Returns {@code Set<String>} stored in this storage.
     *
     * @return {@code Set<String>} of all keys stored in this storage
     * @throws UnsupportedOperationException if operation to retrieve all stored keys is not supported
     * @throws StorageException if there is any problem with internal storage
     */
    public Set<String> getKeys() throws UnsupportedOperationException, StorageException {
        return spi.getKeys();
    }

    /**
     * Checks whether underlying Password Storage is initialized.
     * @return {@code true} in case of initialization passed successfully, {@code false} otherwise.
     */
    public boolean isInitialized() {
        return spi.isInitialized();
    }

    /**
     * Returns {@link Provider} which provides {@link PasswordStorageSpi} for this instance.
     * @return {@link Provider} of this {@link PasswordStorageSpi}
     */
    public Provider getProvider() {
        return provider;
    }

    /**
     * Returns JCA service type of {@link PasswordStorageSpi} for this instance.
     * @return type of service of this {@link PasswordStorageSpi}
     */
    public String getType() {
        return type;
    }
}
