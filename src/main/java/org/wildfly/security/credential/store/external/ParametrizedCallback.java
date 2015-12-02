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
package org.wildfly.security.credential.store.external;

import org.wildfly.security.credential.Credential;

import javax.security.auth.Destroyable;
import javax.security.auth.callback.Callback;
import java.util.Map;

/**
 * Interface to implement when one needs own {@link Callback} get handled by {@code ParametrizedCallbackHandler}.
 *
 * Workflow:
 * <ol>
 *     <li>{@code VaultManager} loads your implementation class from specified {@code module} and creates instance using default constructor</li>
 *     <li>{@code VaultManager} gathers parameters from configuration and calls {@link ParametrizedCallback#initialize(Map)}</li>
 *     <li>{@code VaultManager} creates {@link javax.security.auth.callback.CallbackHandler} and calls it's {@code handle} method with the callback created before</li>
 *     <li>{@code VaultManager} reads {@link Credential} using method {@link ParametrizedCallback#getPassword()}</li>
 *     <li>{@code VaultManager} destroys {@link Credential} in the callback using method {@link ParametrizedCallback#destroy()}. Implement this method as well.</li>
 * </ol>
 *
 * @param <C> credential type
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>.
 * @see ParametrizedCallbackHandler
 */
public interface ParametrizedCallback<C extends Credential> extends Callback, Destroyable {
    /**
     * Method used to initialize {@code Callback} with user parameters. It uses array of {@link String} for keeping fixed order of parameters.
     * @param parameters to initialize {@code Callback} with
     */
    void initialize(Map<String, ?> parameters);

    /**
     * Method to get password from this {@code Callback}
     * Always return new copy of {@code char[]} because internal representation will be destroyed later on.
     * @return password as determined by this {@code Callback}
     */
    C getPassword();

    /**
     * Method to set password to this {@code Callback} is used by {@code CallbackHandler}.
     * @param credential credential to set
     */
    void setPassword(C credential);
}
