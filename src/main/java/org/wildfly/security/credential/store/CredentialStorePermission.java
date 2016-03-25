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

import org.wildfly.common.Assert;
import org.wildfly.security.permission.AbstractNameSetOnlyPermission;
import org.wildfly.security.util.StringEnumeration;
import org.wildfly.security.util.StringMapping;

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
public class CredentialStorePermission extends AbstractNameSetOnlyPermission<CredentialStorePermission> {

    private static final long serialVersionUID = 6248622485149435793L;

    private static final StringEnumeration names = StringEnumeration.of(
        "loadCredentialStore",
        "loadExternalStorePassword",
        "retrieveCredential",
        "modifyCredentialStore"
    );

    private static final StringMapping<CredentialStorePermission> mapping = new StringMapping<>(names, CredentialStorePermission::new);

    /**
     * Load credential store permission.
     */
    public static final CredentialStorePermission LOAD_CREDENTIAL_STORE = mapping.getItemById(0);
    /**
     * Load external store password permission.
     */
    public static final CredentialStorePermission LOAD_EXTERNAL_STORE_PASSWORD = mapping.getItemById(1);
    /**
     * Retrieve credential (password) permission (from credential store).
     */
    public static final CredentialStorePermission RETRIEVE_CREDENTIAL = mapping.getItemById(2);
    /**
     * Store or delete credential (password) permission (from credential store).
     */
    public static final CredentialStorePermission MODIFY_CREDENTIAL_STORE = mapping.getItemById(3);

    private static final CredentialStorePermission allPermission = new CredentialStorePermission("*");

    /**
     * Creates new {@code CredentialStorePermission}
     * @param name of new {@code CredentialStorePermission}
     */
    public CredentialStorePermission(final String name) {
        super(name, names);
    }

    /**
     * Creates new {@code CredentialStorePermission}
     * @param name of new {@code CredentialStorePermission}
     * @param actions have to be {@code null}
     */
    public CredentialStorePermission(final String name, final String actions) {
        this(name);
        requireEmptyActions(actions);
    }

    public CredentialStorePermission withName(final String name) {
        return forName(name);
    }

    /**
     * Get the permission with the given name.
     *
     * @param name the name (must not be {@code null})
     * @return the permission (not {@code null})
     * @throws IllegalArgumentException if the name is not valid
     */
    public static CredentialStorePermission forName(final String name) {
        Assert.checkNotNullParam("name", name);
        return name.equals("*") ? allPermission : mapping.getItemByString(name);
    }
}
