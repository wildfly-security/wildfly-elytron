/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2018 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.auth.jaspi;

import static org.wildfly.security.auth.jaspi._private.ElytronMessages.log;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

import javax.security.auth.message.config.AuthConfigFactory;
import javax.security.auth.message.module.ServerAuthModule;

import org.wildfly.security.auth.jaspi.impl.AuthenticationModuleDefinition;
import org.wildfly.security.auth.jaspi.impl.ElytronAuthConfigProvider;

/**
 * A builder API to assemble JASPIC configuration.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public final class JaspiConfigurationBuilder {

    private final String messageLayer;
    private final String applicationContext;

    private String description;
    private List<AuthenticationModuleDefinition> serverAuthModules = new ArrayList<>();

    private boolean registered = false;

    private JaspiConfigurationBuilder(final String messageLayer, final String applicationContext) {
        this.messageLayer = messageLayer;
        this.applicationContext = applicationContext;
    }

    /**
     * Set the description to be used for the provider once registered.
     *
     * @param description the description to be used for the provider once registered.
     * @return this {@link JaspiConfigurationBuilder} to allow chaining of commands.
     * @throws IllegalStateException if the configuration has already been registered.
     */
    public JaspiConfigurationBuilder setDescription(final String description) {
        assertNotRegistered();
        this.description = description;

        return this;
    }

    /**
     * Add a {@link Supplier<ServerAuthModule>} to be used to create a {@link ServerAuthModule} instance for this message layer
     * and application context combination.
     *
     * @param serverAuthModuleFactory the {@link Supplier<ServerAuthModule>} to be added to the list of module factories.
     * @return this {@link JaspiConfigurationBuilder} to allow chaining of commands.
     * @throws IllegalStateException if the configuration has already been registered.
     */
    public JaspiConfigurationBuilder addAuthModuleFactory(final Supplier<ServerAuthModule> serverAuthModuleFactory) {
        return addAuthModuleFactory(serverAuthModuleFactory, Flag.REQUIRED, Collections.EMPTY_MAP);
    }

    /**
     * Add a {@link Supplier<ServerAuthModule>} to be used to create a {@link ServerAuthModule} instance for this message layer
     * and application context combination.
     *
     * @param serverAuthModuleFactory the {@link Supplier<ServerAuthModule>} to be added to the list of module factories.
     * @param flag the flag to control the handling of the auth module.
     * @param options the configuration options to pass to the module during initialisation.
     * @return this {@link JaspiConfigurationBuilder} to allow chaining of commands.
     * @throws IllegalStateException if the configuration has already been registered.
     */
    public JaspiConfigurationBuilder addAuthModuleFactory(final Supplier<ServerAuthModule> serverAuthModuleFactory, final Flag flag, final Map options) {
        assertNotRegistered();

        serverAuthModules.add(new AuthenticationModuleDefinition(serverAuthModuleFactory, flag, options));

        return this;
    }

    /**
     * Register the assembled configuration against the system wide {@link AuthConfigFactory}.
     *
     * @return The registration ID returned by the factory on registration.
     * @throws IllegalStateException if the configuration has already been registered.
     */
    public String register() {
        return register(AuthConfigFactory.getFactory());
    }

    /**
     * Register the assembled configuration against the supplied {@link AuthConfigFactory}.
     *
     * @param authConfigFactory the {@link AuthConfigFactory} to register the configuration against.
     * @return The registration ID returned by the factory on registration.
     * @throws IllegalStateException if the configuration has already been registered.
     */
    public String register(AuthConfigFactory authConfigFactory) {
        assertNotRegistered();
        registered = true;

        return authConfigFactory.registerConfigProvider(
                new ElytronAuthConfigProvider(messageLayer, applicationContext, serverAuthModules),
                messageLayer, applicationContext, description);
    }

    private void assertNotRegistered() {
        if (registered) {
            throw log.configAlreadyRegistered(messageLayer, applicationContext);
        }
    }

    public static JaspiConfigurationBuilder builder(final String messageLayer, final String applicationContext) {
        return new JaspiConfigurationBuilder(messageLayer, applicationContext);
    }

}
