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
package org.wildfly.security.credential.store.impl;

import static org.wildfly.security._private.ElytronMessages.log;

import java.util.Collections;
import java.util.Map;

import org.wildfly.common.Assert;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.credential.store.CredentialStoreException;
import org.wildfly.security.credential.store.CredentialStoreSpi;
import org.wildfly.security.credential.store.UnsupportedCredentialTypeException;

/**
 * Base class for all command line based {@link CredentialStoreSpi}.
 *
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>
 */
public abstract class CommandCredentialStore extends CredentialStoreSpi {

    /**
     * Attributes passed to this {@code CommandCredentialStore} instance using {@link #initialize(Map)} method.
     */
    protected Map<String, String> attributes = Collections.emptyMap();

    /**
     * credential store name with default value.
     */
    protected String storeName = "abstract-command";

    /**
     * Initialize credential store service with given attributes. This procedure should set {@link #initialized} after
     * successful initialization.
     *
     * @param attributes attributes to used to pass information to credential store service
     * @throws CredentialStoreException if initialization fails due to any reason
     */
    @Override
    public void initialize(Map<String, String> attributes) throws CredentialStoreException {
        this.attributes = attributes;
    }

    /**
     * Check if credential store service supports modification of its store
     *
     * @return {@code true} in case of modification of the store is supported, {@code false} otherwise
     */
    @Override
    public boolean isModifiable() {
        return false;
    }

    /**
     * Check whether credential store service has an entry associated with the given credential alias of specified credential type.
     *
     * @param credentialAlias key to check existence
     * @param credentialType  to check existence in the credential store
     * @return {@code true} in case key exist in store otherwise {@code false}
     * @throws CredentialStoreException           when there is a problem with credential store
     * @throws UnsupportedCredentialTypeException when the credentialType is not supported
     */
    @Override
    public <C extends Credential> boolean exists(String credentialAlias, Class<C> credentialType) throws CredentialStoreException, UnsupportedCredentialTypeException {
        throw log.methodNotImplemented("exists", getName());
    }

    /**
     * Store credential to the credential store service under the given alias. If given alias already contains specific credential type type the credential
     * replaces older one. <em>Note:</em> {@link CredentialStoreSpi} supports storing of multiple entries (credential types) per alias.
     * Each must be of different credential type.
     *
     * @param credentialAlias to store the credential to the store
     * @param credential      instance of {@link Credential} to store
     * @throws CredentialStoreException           when the credential cannot be stored.
     * @throws UnsupportedCredentialTypeException when the credentialType is not supported
     */
    @Override
    public <C extends Credential> void store(String credentialAlias, C credential) throws CredentialStoreException, UnsupportedCredentialTypeException {
        throw log.methodNotImplemented("store", getName());
    }

    /**
     * Retrieve credential stored in the store under the key and of the credential type
     *
     * @param credentialAlias to find the credential in the store
     * @param credentialType  - credential type to retrieve from under the credentialAlias from the store
     * @return instance of {@link Credential} stored in the store
     * @throws CredentialStoreException           - if credentialAlias credentialType combination doesn't exist or credentialAlias cannot be retrieved
     * @throws UnsupportedCredentialTypeException when the credentialType is not supported
     */
    @Override
    public <C extends Credential> C retrieve(String credentialAlias, Class<C> credentialType) throws CredentialStoreException, UnsupportedCredentialTypeException {
        Assert.checkNotNullParam("credentialAlias", credentialAlias);
        Assert.checkNotNullParam("credentialType", credentialType);
        if (credentialType.isAssignableFrom(PasswordCredential.class)) {
            try {
                return credentialType.cast(createPasswordCredential(executePasswordCommand(credentialAlias)));
            } catch (Throwable e) {
                throw log.passwordCommandExecutionProblem(getName(), e);
            }
        } else {
            throw log.credentialTypeNotSupported(credentialType.getName(), getName());
        }
    }

    /**
     * Remove the credentialType with from given alias from the credential store service.
     *
     * @param credentialAlias alias to remove
     * @param credentialType  - credential type to be removed from under the credentialAlias from the credential store service
     * @throws CredentialStoreException           - if credentialAlias credentialType combination doesn't exist or credentialAlias cannot be removed
     * @throws UnsupportedCredentialTypeException when the credentialType is not supported
     */
    @Override
    public <C extends Credential> void remove(String credentialAlias, Class<C> credentialType) throws CredentialStoreException, UnsupportedCredentialTypeException {
        throw log.methodNotImplemented("remove", getName());
    }

    /**
     * Get the name of this credential store.
     * @return name of this credential store
     */
    protected String getName() {
        return storeName;
    }

    abstract char[] executePasswordCommand(String passwordCommand) throws Throwable;

}
