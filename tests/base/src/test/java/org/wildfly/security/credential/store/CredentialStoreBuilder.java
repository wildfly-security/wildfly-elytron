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

import java.security.Provider;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import org.wildfly.security.auth.server.IdentityCredentials;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.credential.store.impl.KeyStoreCredentialStore;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.interfaces.ClearPassword;


/**
 * Utility class to help create {@code KeyStore} for credential store tests dynamically.
 *
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>.
 */
public class CredentialStoreBuilder {

    private String type = "JCEKS";
    private String file;
    private char[] storagePassword;

    private ArrayList<Data> data = new ArrayList<>();
    private Provider[] providers;

    public CredentialStoreBuilder() { }

    static final class Data {
        private String alias;
        private Credential credential;
        private CredentialStore.ProtectionParameter protectionParameter;

        Data(final String alias, final Credential credential, final CredentialStore.ProtectionParameter protectionParameter) {
            this.alias = alias;
            this.credential = credential;
            this.protectionParameter = protectionParameter;
        }

        String getAlias() {
            return alias;
        }

        Credential getCredential() {
            return credential;
        }

        CredentialStore.ProtectionParameter getProtectionParameter() {
            return protectionParameter;
        }
    }

    public static CredentialStoreBuilder get() {
        return new CredentialStoreBuilder();
    }

    public CredentialStoreBuilder setKeyStoreType(String type) {
        this.type = type;
        return this;
    }

    public CredentialStoreBuilder setKeyStoreFile(String file) {
        this.file = file;
        return this;
    }

    public CredentialStoreBuilder setKeyStorePassword(String storagePassword) {
        this.storagePassword = storagePassword.toCharArray();
        return this;
    }

    public CredentialStoreBuilder setKeyStorePassword(char[] storagePassword) {
        this.storagePassword = Arrays.copyOf(storagePassword, storagePassword.length);
        return this;
    }

    public CredentialStoreBuilder addCredential(String alias, Credential credential) {
        data.add(new Data(alias, credential, null));
        return this;
    }

    public CredentialStoreBuilder addPassword(String alias, Password password) {
        return addCredential(alias, new PasswordCredential(password));
    }

    public CredentialStoreBuilder addPassword(String alias, char[] password) {
        return addPassword(alias, ClearPassword.createRaw(ClearPassword.ALGORITHM_CLEAR, password));
    }

    public CredentialStoreBuilder addPassword(String alias, String password) {
        return addPassword(alias, password.toCharArray());
    }

    public CredentialStoreBuilder setProviders(Provider... providers) {
        this.providers = providers;
        return this;
    }

    public void build() throws Exception {
        if (file == null) {
            throw new IllegalStateException("file has to be specified");
        }

        KeyStoreCredentialStore storeImpl = new KeyStoreCredentialStore();

        final Map<String, String> map = new HashMap<>();
        map.put("location", file);
        map.put("create", Boolean.TRUE.toString());
        if (type != null) map.put("keyStoreType", type);
        storeImpl.initialize(
            map,
            new CredentialStore.CredentialSourceProtectionParameter(
                IdentityCredentials.NONE.withCredential(new PasswordCredential(ClearPassword.createRaw(ClearPassword.ALGORITHM_CLEAR, storagePassword)))),
            providers
            );

        for (Data item : data) {
            storeImpl.store(item.getAlias(), item.getCredential(), item.getProtectionParameter());
        }
        storeImpl.flush();
    }

}
