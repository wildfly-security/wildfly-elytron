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

/**
 * Credential reference holder.
 *
 * It contains all necessary information to specify credential store alias and pass it around.
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>
 */
public final class CredentialStoreReference {
    private final String store;
    private final String alias;
    private final char[] clearText;


    /**
     * Creates credential store reference instance using following set of params.
     *
     * @param store the name of store to obtain the credential
     * @param alias the alias of {@link Credential} withing the (credential) store
     */
    public CredentialStoreReference(String store, String alias) {
        this(store, alias, null);
    }

    /**
     * Creates reference to simple clear-text password.
     * @param clearText password in clear text form
     */
    public CredentialStoreReference(char[] clearText) {
        this(null, null, clearText.clone());
    }

    private CredentialStoreReference(String store, String alias, char[] clearText) {
        this.store = store;
        this.alias = alias;
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
     * Gets the password in clear text form
     * @return password
     */
    public char[] getClearText() {
        return clearText;
    }

}
