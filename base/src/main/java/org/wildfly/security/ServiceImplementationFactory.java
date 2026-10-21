/*
 * JBoss, Home of Professional Open Source
 * Copyright 2026 Red Hat, Inc., and individual contributors
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

package org.wildfly.security;

import java.security.Provider;

/**
 * Creates the instances of the service implementation classes that a {@link WildFlyElytronBaseProvider} registers by name.
 * <p>
 * The implementations of the password services live in a different module than the provider. Implementing this
 * interface and registering it with {@link java.util.ServiceLoader} lets that module hand the instances over to the
 * provider, so the provider does not have to load and reflectively instantiate classes of another module.
 */
public interface ServiceImplementationFactory {

    /**
     * Create a new instance of the given implementation class.
     *
     * @param className the name of the implementation class registered with the provider
     * @param provider the provider the service belongs to
     * @return the new instance, or {@code null} if this factory does not provide the given class
     */
    Object newInstance(String className, Provider provider);
}
