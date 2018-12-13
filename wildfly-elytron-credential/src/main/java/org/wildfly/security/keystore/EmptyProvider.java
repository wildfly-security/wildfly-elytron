/*
 * JBoss, Home of Professional Open Source
 * Copyright 2013 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.keystore;

import java.security.Provider;

/**
 * The singleton empty provider.
 */
final class EmptyProvider extends Provider {

    private static final long serialVersionUID = 2185633278059382100L;

    private static final EmptyProvider INSTANCE = new EmptyProvider();

    /**
     * Construct a new instance.
     */
    private EmptyProvider() {
        super("EmptyProvider", 0.0, "Empty Provider");
    }

    /**
     * Get the empty provider instance.
     *
     * @return the empty provider instance
     */
    public static EmptyProvider getInstance() {
        return INSTANCE;
    }
}
