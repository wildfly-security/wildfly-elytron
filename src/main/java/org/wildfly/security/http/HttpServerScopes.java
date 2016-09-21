/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016 Red Hat, Inc., and individual contributors
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
package org.wildfly.security.http;

import java.util.Collection;

/**
 * Interface providing access to context specific {@link HttpScope} instances.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public interface HttpServerScopes {

    /**
     * Returns {@code true} if the specified scope exists.
     *
     * @param scope the scope required.
     * @return {@code true} if the specified scope exists. Otherwise, {@code false}
     */
    boolean exists(Scope scope);

    /**
     * Create the specified scope if available. This method may return the same scope (with the same identifier) if the scope already exists.
     *
     * @param scope the scope required.
     * @return @return the scope specified or {@code null} if not supported.
     */
    HttpScope create(Scope scope);

    /**
     * Get the specified {@link HttpScope} if available.
     *
     * @param scope the type of the scope required.
     * @return the scope specified or {@code null} if not supported.
     */
    HttpScope getScope(Scope scope);

    /**
     * Get the IDs available for the scope specified.
     *
     * @param scope the scope the IDs are required for.
     * @return The IDs available for the scope specified or {@code null} if the scope specified does not support obtaining scopes by ID.
     */
     Collection<String> getScopeIds(Scope scope);

    /**
     * Get the specified {@link HttpScope} with the specified ID.
     *
     * @param scope the type of the scope required.
     * @param id the id of the scope instance required.
     * @return the scope specified or {@code null} if not supported or if the scope with that ID does not exist.
     */
    HttpScope getScope(Scope scope, String id);

}
