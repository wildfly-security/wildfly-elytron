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

package org.wildfly.security;

import java.security.Provider;

/**
 * A security provider which uses a string version, forward compatible with Java 9.
 */
public abstract class VersionedProvider extends Provider {
    private static final long serialVersionUID = 6973461237113228162L;

    /**
     * Constructs a provider with the specified name, version number,
     * and information.
     *
     * @param name the provider name
     * @param version the provider version number string
     * @param info a description of the provider and its services
     */
    protected VersionedProvider(final String name, final String version, final String info) {
        super(name, Double.parseDouble(version), info);
    }
}
