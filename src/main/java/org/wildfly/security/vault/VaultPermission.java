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
package org.wildfly.security.vault;

import java.security.BasicPermission;

/**
 * Vault API specific permission. It can have following target names:
 * <ul>
 *  <li>{@code loadNewVault}</li>
 *  <li>{@code loadExternalStoragePassword}</li>
 *  <li>{@code retrieveSecuredAttribute}</li>
 *  <li>{@code storeSecuredAttribute}</li>
 * </ul>
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>.
 */
public class VaultPermission extends BasicPermission {

    private static final long serialVersionUID = 6248622485149435793L;

    enum Name {
        loadNewVault,
        loadExternalStoragePassword,
        retrieveSecuredAttribute,
        storeSecuredAttribute
        ;

        private final VaultPermission permission;

        Name() {
            permission = new VaultPermission(this);
        }

        VaultPermission getPermission() {
            return permission;
        }

        public static Name of(final String name) {
            try {
                return valueOf(name);
            } catch (IllegalArgumentException ignored) {
                throw new IllegalArgumentException(name.toString());
            }
        }

    }

    /**
     * Load new vault permission.
     */
    public static final VaultPermission LOAD_NEW_VAULT = Name.loadNewVault.getPermission();
    /**
     * Load external password permission.
     */
    public static final VaultPermission LOAD_EXTERNAL_STORAGE_PASSWORD = Name.loadExternalStoragePassword.getPermission();
    /**
     * Retrieve secured attribute (password) from vault permission.
     */
    public static final VaultPermission RETRIEVE_SECURED_ATTRIBUTE = Name.retrieveSecuredAttribute.getPermission();
    /**
     * Store secured attribute (password) from vault permission.
     */
    public static final VaultPermission STORE_SECURED_ATTRIBUTE = Name.storeSecuredAttribute.getPermission();


    /**
     * Creates new {@code VaultPermission} using {@link org.wildfly.security.vault.VaultPermission.Name}
     * @param name of new {@code VaultPermission}
     */
    public VaultPermission(final Name name) {
        super(name.toString());
    }


    /**
     * Creates new {@code VaultPermission}
     * @param name of new {@code VaultPermission}
     */
    public VaultPermission(final String name) {
        this(Name.of(name));
    }

    /**
     * Creates new {@code VaultPermission}
     * @param name of new {@code VaultPermission}
     * @param actions have to be {@code null}
     */
    public VaultPermission(final String name, final String actions) {
        this(name);
        if (actions != null || !actions.isEmpty()) {
            throw new IllegalArgumentException("Actions cannot be specified (use null)");
        }
    }

}
