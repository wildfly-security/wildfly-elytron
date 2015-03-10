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

import java.util.Map;
import java.util.Set;

/**
 * Secured Attribute (password) Storage.
 *
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>.
 */
public interface VaultSpi {

    // general VaultSpi options (should be supported by all implementations)
    /**
     * Value of this option is required and has to be name of vault instance.
     */
    String NAME = "name";
    /**
     * Value of this option denotes file which is used as vault storage.
     */
    String STORAGE_FILE = "storage.file";
    /**
     * Value of this option is storage password. Could be omitted but {@code CALLBACK} has to specified.
     */
    String STORAGE_PASSWORD = "storage.password";
    /**
     *  Format of this option is either {@code [class]} or {@code [class]@[module]}
     *  Default callback handler if {@link VaultCallbackHandler}.
     */
    String CALLBACK_HANDLER = "handler";
    /**
     *  Format of this option is either {@code [class]} or {@code [class]@[module]}
     */
    String CALLBACK = "callback";
    /**
     *  Password class specification. This class has to implement {@link PasswordClass} interface.
     *  Format of this option is either {@code [class]} or {@code [class]@[module]}
     */
    String CALLBACK_PASSWORD_CLASS = CALLBACK + ".passwordClass";

    String CALLBACK_MASKED = CALLBACK + ".maskedPassword";

    String CALLBACK_SALT = CALLBACK + ".salt";

    String CALLBACK_ITERATION = CALLBACK + ".iteration";

    String CALLBACK_PBE_ALGORITHM = CALLBACK + ".algorithm";

    String CALLBACK_PBE_INITIAL_KEY = CALLBACK + ".initialKey";

    /**
     * Returns vault implementation name.
     *
     * The name will be used when vault service will be loading implementation classes and assigning them to handle requests for secret attributes.
     *
     * @return name of {@code Vault} implementation type
     */
    String getVaultType();

    /**
     * Initialize the vault with given options.
     *
     * Options are implementation specific.
     *
     * @param options to initialize the vault
     * @throws VaultException in case of init problems
     */
    void init(Map<String, Object> options) throws VaultException;

    /**
     * Determine if the vault is initialized.
     *
     * @return {@code true} if the vault is already initialized, {@code false} otherwise
     */
    boolean isInitialized();

    /**
     * Get the {@code java.util.Set} of currently stored attributes in the vault.
     *
     * Attributes will be returned in the form of "attribute_name". If the vault contains no attributes it returns empty set.
     *
     * @return the list of attributes that currently reside in the vault
     */
    Set<String> getAttributes();

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
     * @throws VaultException in case of any problem to store the value
     */
    void store(String attribute, char[] value) throws VaultException;

    /**
     * Retrieve the attribute value from the vault.
     *
     * @param attribute to retrieve from the vault
     * @return the value of attribute as {@code char[]}
     * @throws VaultException in case of any problem to retrieve attribute
     */
    char[] retrieve(String attribute) throws VaultException;

    /**
     * Remove an existing attribute from the vault.
     *
     * In case of unsuccessful remove the {@code SecurityVaultException} is thrown.
     * @param attribute to remove from the vault
     * @throws VaultException in case of any problem to remove attribute
     */
    void remove(String attribute) throws VaultException;

}
