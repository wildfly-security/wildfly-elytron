/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2023 Red Hat, Inc., and individual contributors
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
package org.wildfly.security.encryption.client;

import org.wildfly.common.context.ContextManager;
import org.wildfly.common.context.Contextual;
import org.wildfly.security.Version;
import org.wildfly.security.credential.store.CredentialStore;

import java.security.PrivilegedAction;
import java.util.Map;
import java.util.function.Supplier;

import static java.security.AccessController.doPrivileged;

/**
 * A set of resolvers and credential stores used to handle encrypted expressions.
 *
 * @author <a href="mailto:p.paul@redhat.com">Prarthona Paul</a>
 */
public final class EncryptionClientContext implements Contextual<EncryptionClientContext>{
    private static final ContextManager<EncryptionClientContext> CONTEXT_MANAGER = new ContextManager<EncryptionClientContext>(EncryptionClientContext.class);

    private static final Supplier<EncryptionClientContext> SUPPLIER = doPrivileged((PrivilegedAction<Supplier<EncryptionClientContext>>) CONTEXT_MANAGER::getPrivilegedSupplier);

    static {
        Version.getVersion();
        CONTEXT_MANAGER.setGlobalDefaultSupplier(() -> DefaultEncryptionClientContextProvider.DEFAULT);
    }

    EncryptionClientConfiguration encryptionClientConfiguration = new EncryptionClientConfiguration();

    static final EncryptionClientContext EMPTY = new EncryptionClientContext();

    EncryptionClientContext() {
        this(null);
    }

    EncryptionClientContext(EncryptionClientConfiguration encryptionConfig) {
        this.encryptionClientConfiguration = encryptionConfig;
    }

    public EncryptionClientConfiguration getEncryptionClientConfiguration() {
        return encryptionClientConfiguration;
    }

    public EncryptedExpressionResolver getEncryptedExpressionResolver() {
        if (getEncryptionClientConfiguration() == null) {
            throw new InvalidEncryptionClientConfigurationException("Cannot return a resolver because EncryptionClientConfiguration is not initialized");
        } else {
            return getEncryptionClientConfiguration().encryptedExpressionResolver;
        }
    }

    /**
     * Get a new, empty encrypted expression context.
     *
     * @return the new encrypted expression context.
     */
    public static EncryptionClientContext empty() {
        return EMPTY;
    }

    /**
     * Get the current thread's captured encryption client context.
     *
     * @return the current thread's captured encryption client context
     */
    public static EncryptionClientContext captureCurrent() {
        return SUPPLIER.get();
    }


    /**
     * Get a new encryptedExpression context which is the same as this one, but which includes the configurations
     * of the given context at the end of its list.
     *
     * @param other the other encryptedExpression context
     * @return the combined encryptedExpression context
     */
    public EncryptionClientContext with(EncryptionClientContext other, Boolean replaceDefaultResolver) {
        if (other == null) return this;
        return new EncryptionClientContext().with(other.encryptionClientConfiguration, replaceDefaultResolver);
    }

    /**
     * Get a new encryptedExpression context which is the same as this one, but which includes the configurations
     * defined by the {@code config} parameter.
     *
     * @param config the other encryptedExpression context
     * @return the combined encryptedExpression context
     */
    public EncryptionClientContext with(EncryptionClientConfiguration config, Boolean replaceDefaultResolver) {
        if (config == null) return this;
        for (Map.Entry<String, CredentialStore> entry : config.getCredentialStoreMap().entrySet()) {
            this.encryptionClientConfiguration.addCredentialStore(entry.getKey(), entry.getValue());
        }
        this.encryptionClientConfiguration.addEncryptedExpressionResolver(config.encryptedExpressionResolver);
        if (replaceDefaultResolver) {
            this.encryptionClientConfiguration.setDefaultResolverName(config.defaultResolverName);
        }
        return this;
    }


    /**
     * Get a new encryptedExpression context which is the same as this one, but which includes the given object
     * added to the credential store map without a name.
     *
     * @param object the object to add to the context
     * @param configuration the configuration to select
     * @return the combined encryptedExpression context
     */
    public EncryptionClientContext with(Object object, EncryptionClientConfiguration configuration) {
        return with(null, object, configuration);
    }

    /**
     * Get a new encryptedExpression context which is the same as this one, but which includes the given object
     * added to the credential store map with the key indicated by the {@code name} parameter.
     *
     * @param name the name of the object that is being added to the context
     * @param object the object to add to the context
     * @param configuration the configuration to select
     * @return the combined encryptedExpression context
     */
    public EncryptionClientContext with(String name, Object object, EncryptionClientConfiguration configuration) {
        if (configuration == null || object == null) return this;
        if (object instanceof CredentialStore) {
            configuration = configuration.addCredentialStore(name, (CredentialStore) object);
            return new EncryptionClientContext(configuration);
        } else if (object instanceof Map) {
            return new EncryptionClientContext(configuration.useCredentialStoreMap((Map<String, CredentialStore>) object));
        } else if (object instanceof EncryptedExpressionResolver) {
            return new EncryptionClientContext(configuration.addEncryptedExpressionResolver((EncryptedExpressionResolver) object));
        }
        return this;
    }

    /**
     * Get a new encryptedExpression context which is the same as this one, but which removes the credential store
     * indicated by the {@code name} parameter.
     *
     * @param name the name of the object that is being removed from the context
     * @param configuration the configuration to select
     * @return the combined encryptedExpression context
     */
    public EncryptionClientContext withOut(String name, EncryptionClientConfiguration configuration) {
        if (configuration == null || name == null) return this;
        if (configuration.getCredentialStoreMap() == null ||
                configuration.getCredentialStoreMap().isEmpty() ||
                configuration.getCredentialStoreMap().get(name) == null) {
            return this;
        }
        configuration = configuration.removeCredentialStore(name);
        return new EncryptionClientContext(configuration);
    }

    /**
     * Run a privileged action with this encrypted expression context associated for the duration of the task.
     *
     * @param action the action to run under association
     * @param <T> the action return type
     * @return the action return value
     */
    public <T> T run(PrivilegedAction<T> action) {
        return runAction(action);
    }

    public ContextManager<EncryptionClientContext> getInstanceContextManager() {
        return getContextManager();
    }

    public static ContextManager<EncryptionClientContext> getContextManager() {
        return CONTEXT_MANAGER;
    }

}
