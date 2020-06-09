/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2020 Red Hat, Inc., and individual contributors
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
package org.wildfly.security.tool;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Provider;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import org.wildfly.common.Assert;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.credential.store.CredentialStore;
import org.wildfly.security.credential.store.CredentialStoreException;
import org.wildfly.security.credential.store.CredentialStoreSpi;
import org.wildfly.security.credential.store.UnsupportedCredentialTypeException;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.interfaces.ClearPassword;

public class CustomPropertiesCredentialStore extends CredentialStoreSpi {

    public static final String CUSTOM_PROPERTIES_CREDENTIAL_STORE = CustomPropertiesCredentialStore.class.getSimpleName();

    private static final List<String> VALID_ATTRIBUTES = Arrays.asList(new String[]{"location", "modifiable", "create"});

    private final Properties data = new Properties();
    private Path location;
    private boolean modifiable;
    private boolean create;

    @Override
    public void initialize(Map<String, String> attributes, CredentialStore.ProtectionParameter protectionParameter,
            Provider[] providers) throws CredentialStoreException {
        validateAttribute(attributes, VALID_ATTRIBUTES);
        String locationName = attributes.get("location");
        this.location = (locationName == null) ? null : Paths.get(locationName);
        this.modifiable = Boolean.parseBoolean(attributes.getOrDefault("modifiable", "true"));
        this.create = Boolean.parseBoolean(attributes.getOrDefault("create", "false"));
        boolean locationExists = this.location != null && Files.exists(this.location);
        if (this.location != null && !locationExists && !this.create) {
            throw new CredentialStoreException("Location does not exist and cannot be created!");
        }
        if (locationExists) {
            try (FileInputStream is = new FileInputStream(this.location.toFile())) {
                synchronized (this.data) {
                    this.data.load(is);
                }
            } catch (IOException e) {
                throw new CredentialStoreException(e);
            }
        }
        this.initialized = true;
    }

    @Override
    public void flush() throws CredentialStoreException {
        if (!this.modifiable) {
            throw new CredentialStoreException("Store is not modifiable, cannot flush!");
        }
        if (this.location != null) {
            try (OutputStream os = Files.newOutputStream(this.location)) {
                synchronized (this.data) {
                    this.data.store(os, (String) null);
                }
            } catch (IOException e) {
                throw new CredentialStoreException(e);
            }
        }
    }

    @Override
    public boolean isModifiable() {
        return modifiable;
    }

    @Override
    public void store(String credentialAlias, Credential credential, CredentialStore.ProtectionParameter protectionParameter)
            throws CredentialStoreException, UnsupportedCredentialTypeException {
        Assert.checkNotNullParam("credentialAlias", credentialAlias);
        Assert.checkNotNullParam("credential", credential);
        if (!this.modifiable) {
            throw new CredentialStoreException("Store is not modifiable, cannot store!");
        }
        if (credential instanceof PasswordCredential) {
            char[] chars = credential.castAndApply(PasswordCredential.class,
                    c -> c.getPassword().castAndApply(ClearPassword.class, ClearPassword::getPassword));
            synchronized (this.data) {
                this.data.setProperty(credentialAlias, new String(chars));
            }
        } else {
            throw new UnsupportedCredentialTypeException(credential.getClass().getCanonicalName());
        }
    }

    @Override
    public <C extends Credential> C retrieve(String credentialAlias, Class<C> credentialType,
            String credentialAlgorithm, AlgorithmParameterSpec parameterSpec,
            CredentialStore.ProtectionParameter protectionParameter) throws CredentialStoreException {
        String value;
        synchronized (this.data) {
            value = this.data.getProperty(credentialAlias);
        }
        if (value == null) {
            return null;
        }
        return credentialType.cast(new PasswordCredential((Password) ClearPassword.createRaw("clear", value.toCharArray())));
    }

    @Override
    public void remove(String credentialAlias, Class<? extends Credential> credentialType, String credentialAlgorithm,
            AlgorithmParameterSpec parameterSpec) throws CredentialStoreException {
        if (!this.modifiable) {
            throw new CredentialStoreException("Store is not modifiable, cannot remove!");
        }
        synchronized (this.data) {
            this.data.remove(credentialAlias);
        }
    }

    @Override
    public Set<String> getAliases() throws UnsupportedOperationException, CredentialStoreException {
        synchronized (this.data) {
            return this.data.stringPropertyNames();
        }
    }
}
