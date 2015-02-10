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

import java.net.URI;
import java.util.List;
import java.util.Map;

/**
 * Secured Attribute (password) Storage.
 *
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>.
 */
public interface Vault {

    /**
     * Initialize the vault with given options.
     *
     * Options are implementation specific.
     *
     * @param options to initialize the vault
     * @throws SecurityVaultException in case of init problems
     */
    void init(Map<String, Object> options) throws SecurityVaultException;

    /**
     * Initialize vault using vault URI.
     *
     * @param vault the URI which denotes all needed parameters to initialize the vault
     * @throws SecurityVaultException in case of init problems
     */
    void init(URI vault) throws SecurityVaultException;

    /**
     * Determine if the vault is initialized.
     *
     * @return {@code true} if the vault is already initialized, {@code false} otherwise
     */
    boolean isInitialized();

    /**
     * Get the {@code java.util.List} of currently stored attributes in the vault.
     *
     * Attributes will be returned in the form of "attribute_name". If the vault contains no attributes it returns empty list.
     *
     * @return the list of attributes that currently reside in the vault
     */
    List<String> getAttributes();

    /**
     * Check whether an attribute value exists in the vault.
     *
     * @param attribute the name of attribute to check
     * @return {@code true} if attribute exits otherwise {@code false}
     */
    boolean exists(String attribute);

    /**
     * Store an attribute value to the vault.
     *
     * @param attribute name of the attribute
     * @param value of secret attribute (e.g. password)
     * @throws SecurityVaultException in case of any problem to store the value
     */
    void store(String attribute, char[] value) throws SecurityVaultException;

    /**
     * Retrieve the attribute value from the vault.
     *
     * @param attribute to retrieve from the vault
     * @return the value of attribute as {@code char[]}
     * @throws SecurityVaultException in case of any problem to retrieve attribute
     */
    char[] retrieve(String attribute) throws SecurityVaultException;

    /**
     * Remove an existing attribute from the vault.
     *
     * In case of unsuccessful remove the {@code SecurityVaultException} is thrown.
     * @param attribute to remove from the vault
     * @throws SecurityVaultException in case of any problem to remove attribute
     */
    void remove(String attribute) throws SecurityVaultException;

}
