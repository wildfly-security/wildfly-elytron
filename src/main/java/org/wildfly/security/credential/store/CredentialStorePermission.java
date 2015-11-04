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

import java.security.BasicPermission;

/**
 * Credential Store API specific permission. It can have following target names:
 * <ul>
 *  <li>{@code loadCredentialStore}</li>
 *  <li>{@code loadExternalStorePassword}</li>
 *  <li>{@code retrieveCredential}</li>
 *  <li>{@code modifyCredentialStore}</li>
 * </ul>
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>.
 */
public class CredentialStorePermission extends BasicPermission {

    private static final long serialVersionUID = 6248622485149435793L;

    enum Name {
        loadCredentialStore,
        loadExternalStorePassword,
        retrieveCredential,
        modifyCredentialStore
        ;

        private final CredentialStorePermission permission;

        Name() {
            permission = new CredentialStorePermission(this);
        }

        CredentialStorePermission getPermission() {
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
     * Load credential store permission.
     */
    public static final CredentialStorePermission LOAD_CREDENTIAL_STORE = Name.loadCredentialStore.getPermission();
    /**
     * Load external store password permission.
     */
    public static final CredentialStorePermission LOAD_EXTERNAL_STORE_PASSWORD = Name.loadExternalStorePassword.getPermission();
    /**
     * Retrieve credential (password) permission (from credential store).
     */
    public static final CredentialStorePermission RETRIEVE_CREDENTIAL = Name.retrieveCredential.getPermission();
    /**
     * Store or delete credential (password) permission (from credential store).
     */
    public static final CredentialStorePermission MODIFY_CREDENTIAL_STORE = Name.modifyCredentialStore.getPermission();


    /**
     * Creates new {@code CredentialStorePermission} using {@link CredentialStorePermission.Name}
     * @param name of new {@code CredentialStorePermission}
     */
    public CredentialStorePermission(final Name name) {
        super(name.toString());
    }


    /**
     * Creates new {@code CredentialStorePermission}
     * @param name of new {@code CredentialStorePermission}
     */
    public CredentialStorePermission(final String name) {
        this(Name.of(name));
    }

    /**
     * Creates new {@code CredentialStorePermission}
     * @param name of new {@code CredentialStorePermission}
     * @param actions have to be {@code null}
     */
    public CredentialStorePermission(final String name, final String actions) {
        this(name);
        if (actions != null || !actions.isEmpty()) {
            throw new IllegalArgumentException("Actions cannot be specified (use null)");
        }
    }

}
