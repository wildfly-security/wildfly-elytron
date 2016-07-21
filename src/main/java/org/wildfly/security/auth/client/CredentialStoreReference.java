/*
 * JBoss, Home of Professional Open Source
 * Copyright 2016 Red Hat, Inc., and individual contributors
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
package org.wildfly.security.auth.client;

import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.PasswordCredential;

/**
 * Credential reference holder.
 *
 * It contains all necessary information to specify credential store alias and pass it around.
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>
 */
public final class CredentialStoreReference {
    private final String store;
    private final String alias;
    private final Class<? extends Credential> type;
    private final char[] clearText;

    /**
     * Creates credential store reference instance using following set of params.
     *
     * @param store the name of store to obtain the credential
     * @param alias the alias of {@link Credential} withing the (credential) store
     * @param typeName the credential type of wanted {@link Credential}
     */
    public CredentialStoreReference(String store, String alias, String typeName) {
        this(store, alias, typeName, null, null);
    }

    /**
     * Creates credential store reference instance using following set of params.
     *
     * @param store the name of store to obtain the credential
     * @param alias the alias of {@link Credential} withing the (credential) store
     */
    public CredentialStoreReference(String store, String alias) {
        this(store, alias, null, null, null);
    }

    /**
     * Creates credential store reference instance using following set of params.
     *
     * @param store the name of store to obtain the credential
     * @param alias the alias of {@link Credential} withing the (credential) store
     * @param type the credential type of wanted {@link Credential}
     */
    public CredentialStoreReference(String store, String alias, Class<? extends Credential> type) {
        this(store, alias, null, type, null);
    }

    /**
     * Creates reference to simple clear-text password.
     * @param clearText password in clear text form
     */
    public CredentialStoreReference(char[] clearText) {
        this(null, null, null, null, clearText.clone());
    }

    private CredentialStoreReference(String store, String alias, String typeName, Class<? extends Credential> type, char[] clearText) {
        this.store = store;
        this.alias = alias;
        if (type != null) {
            this.type = type;
        } else {
            this.type = getCredentialType(typeName);
        }
        this.clearText = clearText;
    }

    /**
     * Gets the credential store name
     * @return store name
     */
    public String getStore() {
        return store;
    }

    /**
     * Gets the alias
     * @return alias
     */
    public String getAlias() {
        return alias;
    }

    /**
     * Gets the credential type
     * @return credential type
     */
    public Class<? extends Credential> getType() {
        return type;
    }

    /**
     * Gets the password in clear text form
     * @return password
     */
    public char[] getClearText() {
        return clearText;
    }

    private static <C extends Credential> Class<C> getCredentialType(String typeName) {
        if (typeName != null && !typeName.isEmpty()) {
            // TODO Elytron -> ELY-590: Add support for loading custom credential types from providers
            Class<? extends Credential> credentialClass = null;
            try {
                credentialClass = (Class<? extends Credential>) Credential.class.getClassLoader().loadClass(typeName);
            } catch (ClassNotFoundException e) {
                e.printStackTrace();

            }
            return (Class<C>)credentialClass;
        }
        // default
        return (Class<C>) PasswordCredential.class;
    }

}
