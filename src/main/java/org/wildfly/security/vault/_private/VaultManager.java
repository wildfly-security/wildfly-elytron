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

import org.jboss.modules.Module;
import org.jboss.modules.ModuleIdentifier;
import org.jboss.modules.ModuleLoadException;
import org.jboss.modules.ModuleLoader;
import org.wildfly.security.vault.VaultException;
import org.wildfly.security.vault.VaultPermission;
import org.wildfly.security.vault.VaultRuntimeException;
import org.wildfly.security.vault.VaultSpi;
import org.wildfly.security.vault.VaultURIParser;

import javax.security.auth.callback.UnsupportedCallbackException;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.PrivilegedAction;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.ServiceLoader;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import static java.security.AccessController.doPrivileged;
import static org.wildfly.security._private.ElytronMessages.log;

/**
 * VaultManager handles multiple {@link org.wildfly.security.vault.VaultSpi} possibly loaded from different modules.
 *
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>.
 */
public final class VaultManager {

    static final String DEFAULT_VAULT_CLASS_NAME = ElytronVault.class.getName();

    // map of current vaults
    private ConcurrentHashMap<String, VaultInfo> vaults = new ConcurrentHashMap<>();

    VaultManager() {
    }

    @Override
    protected Object clone() throws CloneNotSupportedException {
        throw new UnsupportedOperationException();
    }

    public void registerNewVaultInstance(final String vaultUri, final String module, final String className) throws VaultException {
        registerNewVaultInstance(getVaultUri(vaultUri), module, className);
    }

    public void registerNewVaultInstance(final URI vaultUri, final String module, final String className) throws VaultException {
        VaultURIParser parser = new VaultURIParser(vaultUri);
        VaultInfo vi = new VaultInfo();
        vi.module = module;
        vi.className = className;
        vi.vaultUri = vaultUri;
        vaults.put(parser.getName(), vi);
    }

    public void registerNewVaultInstance(final URI vaultUri, final String module) throws VaultException {
        registerNewVaultInstance(vaultUri, module, null);
    }


    public void registerNewVaultInstance(final URI vaultUri) throws VaultException {
        registerNewVaultInstance(vaultUri, null, null);
    }

    public void unregisterVault(final String name) {
        VaultInfo vi = vaults.remove(name);
        if (vi == null) {
            throw log.vaultDoesNotExist(name);
        }
    }

    private VaultSpi getDefaultVault() throws VaultException {
        ServiceLoader<VaultSpi> loader = ServiceLoader.load(VaultSpi.class);
        return loader.iterator().next();
    }

    private VaultSpi loadAndInitializeVault(final VaultInfo vaultInfo) throws VaultException {
        if (vaultInfo.vault != null) {
            return vaultInfo.vault;
        } else {
            final SecurityManager sm = System.getSecurityManager();
            if (sm != null) {
                sm.checkPermission(VaultPermission.LOAD_NEW_VAULT);
            }
            VaultURIParser parser = new VaultURIParser(vaultInfo.vaultUri);
            String vaultName = parser.getName();
            Map<String, Object> options = parser.getOptionsMap();
            ExternalPasswordLoader passwordLoader = new ExternalPasswordLoader();
            Object password = null;
            try {
                password = passwordLoader.loadPassword(options);
            } catch (IllegalAccessException | InstantiationException | IOException | UnsupportedCallbackException | NoSuchMethodException e) {
                throw new VaultException(e);
            }

            // remove unwanted options from the map (like all with prefix VaultSpi.CALLBACK and VaultSpi.CALLBACK_HANDLER
            filterVaultOptions(options, VaultSpi.CALLBACK_HANDLER, VaultSpi.CALLBACK);

            options.put(VaultSpi.STORAGE_PASSWORD, password);
            options.put(VaultSpi.STORAGE_FILE, parser.getStorageFile());
            options.put(VaultSpi.NAME, vaultName);

            VaultSpi vlt = getVaultImplementation(vaultInfo.module, vaultInfo.className);
            synchronized (vaultInfo) {
                vlt.init(options);
                log.logVaultInitialized(vaultName, vlt.getVaultType());
                vaultInfo.vault = vlt;
            }
            return vaultInfo.vault;
        }
    }

    private static void filterVaultOptions(Map<String, Object> options, String... prefix) {
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
     * This method just loads the vault implementation class (no initialization).
     *
     * @param module
     * @param className
     * @return
     */
    private VaultSpi getVaultImplementation(final String module, final String className) throws VaultException {
        if (module != null) {
            final Module vaultModule = doPrivileged(new PrivilegedAction<Module>() {
                @Override
                public Module run() {
                    ModuleLoader loader = Module.getCallerModuleLoader();
                    try {
                        return loader.loadModule(ModuleIdentifier.fromString(module));
                    } catch (ModuleLoadException e) {
                        throw log.vaultRuntimeException(e);
                    }
                }
            });

            ServiceLoader<VaultSpi> loader = vaultModule.loadService(VaultSpi.class);
            VaultSpi v = null;
            Iterator<VaultSpi> it = loader.iterator();
            if (className != null) {
                while(it.hasNext()) {
                    v = it.next();
                    if (className.equals(v.getClass().getName())) {
                        return v;
                    }
                }
                throw log.vaultClassImplementationNotFound(className + "@" + module);
            } else {
                if (it.hasNext()) {
                    return it.next();
                }
                throw log.vaultDoesNotExist("@" + module);
            }
        }
        return getDefaultVault();
    }

    public void store(final String attributeQueryUri, final char[] value) throws VaultException, URISyntaxException {
        final SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            sm.checkPermission(VaultPermission.MODIFY_VAULT);
        }
        VaultURIParser p = new VaultURIParser(attributeQueryUri);
        VaultSpi v = getVault(p.getName());
        v.store(p.getAttribute(), value);
    }

    public char[] retrieve(final String attributeQueryUri) throws VaultException, URISyntaxException {
        final SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            sm.checkPermission(VaultPermission.RETRIEVE_SECURED_ATTRIBUTE);
        }
        VaultURIParser p = new VaultURIParser(attributeQueryUri);
        VaultSpi v = getVault(p.getName());
        return v.retrieve(p.getAttribute());
    }

    public void remove(final String attributeQueryUri) throws VaultException, URISyntaxException {
        final SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            sm.checkPermission(VaultPermission.MODIFY_VAULT);
        }
        VaultURIParser p = new VaultURIParser(attributeQueryUri);
        VaultSpi v = getVault(p.getName());
        v.remove(p.getAttribute());
    }


    /**
     * Get all attributes stored in particular vault
     * @param vaultName vault name to get attributes fromm
     * @return {@code List<String>} attribute names
     */
    public Set<String> getAttributes(final String vaultUri) throws VaultException {
        final SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            sm.checkPermission(VaultPermission.RETRIEVE_SECURED_ATTRIBUTE);
        }
        return getVault(getVaultUri(vaultUri)).getAttributes();
    }

    /**
     * Check whether the attribute defined by {@code attributeQueryUri} exists.
     * Note that {@code attributeQueryUri} contains vault name so the vault is denoted by that name.
     *
     * @param attributeQueryUri to check
     * @return true or false depending on attribute existence
     * @throws URISyntaxException in case of badly formed {@code attributeQueryUri}
     */
    public boolean exists(final String attributeQueryUri) throws URISyntaxException, VaultException {
        final SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            sm.checkPermission(VaultPermission.RETRIEVE_SECURED_ATTRIBUTE);
        }
        VaultURIParser p = new VaultURIParser(attributeQueryUri);
        return getVault(p.getName()).exists(p.getAttribute());
    }

    private URI getVaultUri(final String vaultUri) throws VaultRuntimeException {
        try {
            return new URI(vaultUri);
        } catch (URISyntaxException e) {
            throw log.vaultRuntimeException(e);
        }
    }

    /**
     * Returns Vault as {@link VaultSpi} from currently managed Vaults.
     * @param vault Vault {@link java.net.URI} which represents at least name of the vault to retrieve. Minimal URI is {@code vault://vault_name}
     * @return null in case there is no such vault name present or {@link VaultSpi} otherwise
     */
    private VaultSpi getVault(final URI vault) throws VaultException {
        VaultURIParser p = new VaultURIParser(vault);
        return getVault(p.getName());
    }

    /**
     * Returns Vault as {@link VaultSpi} from currently managed Vaults.
     * @param name the name of the Vault to retrieve
     * @return null in case there is no such vault name present or {@link VaultSpi} otherwise
     * @throws VaultRuntimeException in case the vault does not exist
     */
    private VaultSpi getVault(final String name) throws VaultException {
        VaultInfo vi = vaults.get(name);
        if (vi == null) {
            throw log.vaultDoesNotExist(name);
        }

        if (vi.vault == null) {
            return loadAndInitializeVault(vi);
        }
        return vi.vault;
    }


}
