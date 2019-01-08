/*
 * Copyright 2018 Red Hat, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wildfly.security.auth.jaspi.impl;

import java.util.Map;
import java.util.function.Supplier;

import javax.security.auth.message.module.ServerAuthModule;

import org.wildfly.security.auth.jaspi.Flag;

/**
 * A definition for a single {@link ServerAuthModule}.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class AuthenticationModuleDefinition {

    private final Supplier<ServerAuthModule> serverAuthModuleFactory;
    private final Flag flag;
    private final Map options;

    /**
     * Construct a new instance of a module definition.
     *
     * @param serverAuthModuleFactory the factory to create an instance of the {@link ServerAuthModule}.
     * @param flag the flag to indicate how this module will be handled.
     * @param options configuration options to pass into the module during initialisation.
     */
    public AuthenticationModuleDefinition(final Supplier<ServerAuthModule> serverAuthModuleFactory, final Flag flag, final Map options) {
        this.serverAuthModuleFactory = serverAuthModuleFactory;
        this.flag = flag;
        this.options = options;
    }

    /**
     * Get the factory to create an instance of the {@link ServerAuthModule}.
     *
     * @return the factory to create an instance of the {@link ServerAuthModule}.
     */
    Supplier<ServerAuthModule> getServerAuthModuleFactory() {
        return serverAuthModuleFactory;
    }

    /**
     * Get the {@link Flag} controlling the handling of the module.
     *
     * @return the {@link Flag} controlling the handling of the module.
     */
    Flag getFlag() {
        return flag;
    }

    /**
     * Get the module options to be passed into the module during initialisation.
     *
     * @return the module options to be passed into the module during initialisation.
     */
    Map getOptions() {
        return options;
    }

}
