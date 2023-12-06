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

package org.wildfly.security.auth.client;

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
public final class EncryptedExpressionContext implements Contextual<EncryptedExpressionContext>{
    private static final ContextManager<EncryptedExpressionContext> CONTEXT_MANAGER = new ContextManager<EncryptedExpressionContext>(EncryptedExpressionContext.class);

    private static final Supplier<EncryptedExpressionContext> SUPPLIER = doPrivileged((PrivilegedAction<Supplier<EncryptedExpressionContext>>) CONTEXT_MANAGER::getPrivilegedSupplier);

    static {
        Version.getVersion();
        CONTEXT_MANAGER.setGlobalDefaultSupplier(() -> EncryptedExpressionContext.EMPTY);
    }

    EncryptedExpressionConfig encryptedExpressionConfig = new EncryptedExpressionConfig();

    static final EncryptedExpressionContext EMPTY = new EncryptedExpressionContext();

    EncryptedExpressionContext() {
        this(null);
    }

    EncryptedExpressionContext(EncryptedExpressionConfig encryptionConfig) {
        this.encryptedExpressionConfig = encryptionConfig;
    }

    /**
     * Get a new, empty encrypted expression context.
     *
     * @return the new encrypted expression context.
     */
    public static EncryptedExpressionContext empty() {
        return EMPTY;
    }

    /**
     * Get the current thread's captured authentication context.
     *
     * @return the current thread's captured authentication context
     */
    public static EncryptedExpressionContext captureCurrent() {
        return SUPPLIER.get();
    }


    /**
     * Get a new encryptedExpression context which is the same as this one, but which includes the configurations
     * of the given context at the end of its list.
     *
     * @param other the other encryptedExpression context
     * @return the combined encryptedExpression context
     */
    public EncryptedExpressionContext with(EncryptedExpressionContext other, Boolean replaceDefaultResolver) {
        if (other == null) return this;
        return new EncryptedExpressionContext().with(other.encryptedExpressionConfig, replaceDefaultResolver);
    }

    /**
     * Get a new encryptedExpression context which is the same as this one, but which includes the configurations
     * defined by the {@code config} parameter.
     *
     * @param config the other encryptedExpression context
     * @return the combined encryptedExpression context
     */
    public EncryptedExpressionContext with(EncryptedExpressionConfig config, Boolean replaceDefaultResolver) {
        if (config == null) return this;
        for (Map.Entry<String, CredentialStore> entry : config.getCredentialStoreMap().entrySet()) {
            this.encryptedExpressionConfig.addCredentialStore(entry.getKey(), entry.getValue());
        }
        this.encryptedExpressionConfig.addEncryptedExpressionResolver(config.encryptedExpressionResolver);
        if (replaceDefaultResolver) {
            this.encryptedExpressionConfig.setDefaultResolverName(config.defaultResolverName);
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
    public EncryptedExpressionContext with(Object object, EncryptedExpressionConfig configuration) {
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
    public EncryptedExpressionContext with(String name, Object object, EncryptedExpressionConfig configuration) {
        if (configuration == null || object == null) return this;
        if (object instanceof CredentialStore) {
            configuration = configuration.addCredentialStore(name, (CredentialStore) object);
            return new EncryptedExpressionContext(configuration);
        } else if (object instanceof Map) {
            return new EncryptedExpressionContext(configuration.useCredentialStoreMap((Map<String, CredentialStore>) object));
        } else if (object instanceof EncryptedExpressionResolver) {
            return new EncryptedExpressionContext(configuration.addEncryptedExpressionResolver((EncryptedExpressionResolver) object));
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
    public EncryptedExpressionContext withOut(String name, EncryptedExpressionConfig configuration) {
        if (configuration == null || name == null) return this;
        if (configuration.getCredentialStoreMap() == null ||
                configuration.getCredentialStoreMap().isEmpty() ||
                configuration.getCredentialStoreMap().get(name) == null) {
            return this;
        }
        configuration = configuration.removeCredentialStore(name);
        return new EncryptedExpressionContext(configuration);
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

    public ContextManager<EncryptedExpressionContext> getInstanceContextManager() {
        return getContextManager();
    }

    public static ContextManager<EncryptedExpressionContext> getContextManager() {
        return CONTEXT_MANAGER;
    }

}
