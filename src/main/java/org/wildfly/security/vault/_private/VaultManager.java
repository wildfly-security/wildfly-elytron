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
package org.wildfly.security.vault._private;

import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.storage.PasswordStorage;
import org.wildfly.security.storage.StorageException;
import org.wildfly.security.storage.UnsupportedPasswordClassException;
import org.wildfly.security.vault.VaultException;
import org.wildfly.security.vault.VaultPermission;
import org.wildfly.security.vault.VaultURIParser;

import javax.security.auth.callback.UnsupportedCallbackException;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static org.wildfly.security._private.ElytronMessages.log;

/**
 * VaultManager handles multiple {@link PasswordStorage} instances possibly loaded from different {@link java.security.Provider}.
 *
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>.
 */
public final class VaultManager {

    // map of current vaults
    private ConcurrentHashMap<String, VaultInfo> vaults = new ConcurrentHashMap<>();

    VaultManager() {
    }

    @Override
    protected Object clone() throws CloneNotSupportedException {
        throw new UnsupportedOperationException();
    }

    /**
     * Registers new Vault based on {@code vaultUri} parameter to the VaultManager.
     *
     * Vault is lazy loaded when it is accessed for the first time.
     *
     * @param vaultUri - {@code URI} which represents Vault
     * @throws VaultException - throws in case of vaultUri parsing problem
     */
    public void registerNewVaultInstance(final String vaultUri) throws VaultException {
        registerNewVaultInstance(getVaultUri(vaultUri));
    }

    /**
     * Registers new Vault based on {@code vaultUri} parameter to the VaultManager.
     *
     * Vault is lazy loaded when it is accessed for the first time.
     *
     * @param vaultUri {@code URI} which represents Vault
     * @throws VaultException thrown in case of vaultUri parsing problem
     */
    public void registerNewVaultInstance(final URI vaultUri) throws VaultException {
        VaultURIParser parser = new VaultURIParser(vaultUri);
        VaultInfo vi = new VaultInfo();
        vi.vaultUri = vaultUri;
        vaults.put(parser.getName(), vi);
    }

    /**
     *  Un-registers Vault with given name.
     *
     * @param name of the Vault to un-register
     * @throws VaultException when vault with given name doesn't exist
     */
    public void unregisterVault(final String name) throws VaultException {
        VaultInfo vi = vaults.remove(name);
        if (vi == null) {
            throw log.vaultDoesNotExist(name);
        }
    }

    /**
     *  Un-registers Vault with given name.
     *
     * @param vaultUri {@code URI} which represents Vault
     * @throws VaultException when vault with given name doesn't exist
     */
    public void unregisterVault(final URI vaultUri) throws VaultException {
        VaultURIParser parser = new VaultURIParser(vaultUri);
        unregisterVault(parser.getName());
    }

    /**
     * Returns {@link Enumeration} of Vault names handled by this {@code VaultManager}
     * @return vault names empty {@code Enumeration<String>} if {@code VaultManager} is empty.
     */
    public Enumeration<String> listVaults() {
        return vaults.keys();
    }

    /**
     * Checks whether specified Vault is registered with this {@link VaultManager}.
     *
     * @param name of Vault to check existence
     * @return {@code true} if the Vault is registered, {@code false} otherwise
     */
    public boolean checkVaultExist(String name) {
        return vaults.containsKey(name);
    }

    /**
     * Initializes and loads vault.
     *
     * Vaults are lazy loaded/initialized. This method enables clients to load and initialize it on demand.
     *
     * @param name of vault to initialize
     * @throws VaultException when something goes wrong
     */
    public void initializeVault(String name) throws VaultException {
        getStorage(name);
    }

    private PasswordStorage getDefaultPasswordStorage() throws NoSuchAlgorithmException {
        return PasswordStorage.getInstance(KeystorePasswordStorage.KEY_STORE_PASSWORD_STORAGE);
    }

    private PasswordStorage getPasswordStorage(final String storageType, final String providerName) throws NoSuchAlgorithmException, NoSuchProviderException {
        if (storageType != null) {
            if (providerName != null) {
                return PasswordStorage.getInstance(storageType, providerName);
            } else {
                return PasswordStorage.getInstance(storageType);
            }
        } else {
            return getDefaultPasswordStorage();
        }
    }

    private PasswordStorage loadAndInitializeVault(final VaultInfo vaultInfo) throws VaultException {
        if (vaultInfo.vault != null) {
            return vaultInfo.vault;
        } else {
            final SecurityManager sm = System.getSecurityManager();
            if (sm != null) {
                sm.checkPermission(VaultPermission.LOAD_NEW_VAULT);
            }
            VaultURIParser parser = new VaultURIParser(vaultInfo.vaultUri);
            String vaultName = parser.getName();
            Map<String, String> options = parser.getOptionsMap();
            ExternalPasswordLoader passwordLoader = new ExternalPasswordLoader();
            char[] password;
            try {
                password = passwordLoader.loadPassword(options);
            } catch (IllegalAccessException | InstantiationException | IOException | UnsupportedCallbackException | NoSuchMethodException e) {
                throw new VaultException(e);
            }

            // remove unwanted options from the map (like all with prefix VaultSpi.CALLBACK and VaultSpi.CALLBACK_HANDLER
            filterVaultOptions(options, KeystorePasswordStorage.CALLBACK_HANDLER, KeystorePasswordStorage.CALLBACK);
            options.put(KeystorePasswordStorage.STORAGE_PASSWORD, new String(password));
            options.put(KeystorePasswordStorage.STORAGE_FILE, parser.getStorageFile());
            options.put(KeystorePasswordStorage.NAME, vaultName);

            PasswordStorage vlt = null;
            try {
                vlt = getPasswordStorage(vaultInfo.storageType, vaultInfo.providerName);
            } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
                throw new VaultException(e);
            }
            synchronized (vaultInfo) {
                try {
                    vlt.initialize(options);
                } catch (StorageException e) {
                    throw new VaultException(e);
                }
                log.logVaultInitialized(vaultName, vlt.getType());
                vaultInfo.vault = vlt;
            }
            return vaultInfo.vault;
        }
    }

    private static void filterVaultOptions(Map<String, String> options, String... prefix) {
        HashSet<String> toRemove = new HashSet<>();
        for (String key: options.keySet()) {
            for (String p: prefix) {
                if (key.startsWith(p)) {
                    toRemove.add(key);
                    break;
                }
            }
        }
        options.keySet().removeAll(toRemove);
    }

    /**
     * Store new secured attribute in the specified password storage
     *
     * @param attributeQueryUri {@code URI} which specifies the Vault and attribute name
     * @param value secured attribute which will be stored under attribute specified in {@code attributeQueryUri}
     * @throws URISyntaxException if {@code attributeQueryUri} cannot be parsed
     * @throws VaultException if anything with the storage goes wrong
     */
    public void store(final String attributeQueryUri, final char[] value) throws URISyntaxException, VaultException {
        final SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            sm.checkPermission(VaultPermission.MODIFY_VAULT);
        }
        VaultURIParser p = new VaultURIParser(attributeQueryUri);
        PasswordStorage storage = getStorage(p.getName());
        try {
            ClearPassword clearPassword = (ClearPassword) PasswordFactory.getInstance(ClearPassword.ALGORITHM_CLEAR)
                    .generatePassword(new ClearPasswordSpec(value));
            storage.store(p.getAttribute(), ClearPassword.class, clearPassword);
        } catch (NoSuchAlgorithmException | UnsupportedPasswordClassException | StorageException | InvalidKeySpecException e) {
            throw new VaultException(e);
        }
    }

    /**
     * Retrieve secured attribute from the specified password storage
     *
     * @param attributeQueryUri {@code URI} which specifies the storage and attribute name
     * @return clear text secured attribute
     * @throws URISyntaxException if {@code attributeQueryUri} cannot be parsed
     * @throws VaultException if anything with the storage goes wrong or attribute doesn't exist in the storage
     */
    public char[] retrieve(final String attributeQueryUri) throws URISyntaxException, VaultException {
        final SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            sm.checkPermission(VaultPermission.RETRIEVE_SECURED_ATTRIBUTE);
        }
        VaultURIParser p = new VaultURIParser(attributeQueryUri);
        PasswordStorage storage = getStorage(p.getName());
        try {
            return storage.retrieve(p.getAttribute(), ClearPassword.class).getPassword();
        } catch (StorageException | UnsupportedPasswordClassException e) {
            throw new VaultException(e);
        }
    }

    /**
     * Remove secured attribute from the specified Vault
     *
     * @param attributeQueryUri {@code URI} which specifies the Vault and attribute name
     * @throws URISyntaxException if {@code attributeQueryUri} cannot be parsed
     * @throws VaultException if anything with the storage goes wrong
     */
    public void remove(final String attributeQueryUri) throws URISyntaxException, VaultException {
        final SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            sm.checkPermission(VaultPermission.MODIFY_VAULT);
        }
        VaultURIParser p = new VaultURIParser(attributeQueryUri);
        PasswordStorage storage = getStorage(p.getName());
        try {
            storage.remove(p.getAttribute(), ClearPassword.class);
        } catch (StorageException | UnsupportedPasswordClassException e) {
            throw new VaultException(e);
        }
    }

    /**
     * Check whether the attribute defined by {@code attributeQueryUri} exists.
     * Note that {@code attributeQueryUri} contains vault name so the vault is denoted by that name.
     *
     * @param attributeQueryUri to check
     * @return true or false depending on attribute existence
     * @throws URISyntaxException in case of badly formed {@code attributeQueryUri}
     * @throws VaultException if anything with the storage goes wrong
     */
    public boolean exists(final String attributeQueryUri) throws URISyntaxException, VaultException {
        final SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            sm.checkPermission(VaultPermission.RETRIEVE_SECURED_ATTRIBUTE);
        }
        VaultURIParser p = new VaultURIParser(attributeQueryUri);
        PasswordStorage storage = getStorage(p.getName());
        try {
            return  storage.exists(p.getAttribute(), ClearPassword.class);
        } catch (StorageException | UnsupportedPasswordClassException e) {
            throw new VaultException(e);
        }
    }

    private URI getVaultUri(final String vaultUri) throws VaultException {
        try {
            return new URI(vaultUri);
        } catch (URISyntaxException e) {
            throw log.vaultException(e);
        }
    }

    /**
     * Returns {@link PasswordStorage} from currently managed Vaults.
     * In case the storage is not initialized it loads the {@link PasswordStorage} and initialize it.
     *
     * @param name the name of the storage to retrieve
     * @return {@code null} in case there is no such {@link PasswordStorage} name present or {@link PasswordStorage} otherwise
     * @throws VaultException in case the storage does not exist
     */
    private PasswordStorage getStorage(final String name) throws VaultException {
        VaultInfo vi = vaults.get(name);
        if (vi == null) {
            throw log.vaultDoesNotExist(name);
        }

        if (vi.vault == null) {
            return loadAndInitializeVault(vi);
        } else if (! vi.vault.isInitialized()) {
            return loadAndInitializeVault(vi);
        }
        return vi.vault;
    }

}
