/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2017 Red Hat, Inc., and individual contributors
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
package org.wildfly.security.http.util.sso;

import org.wildfly.security.auth.server.SecurityIdentity;

/**
 * Manages the persistence of a {@link SingleSignOn} entry.
 * @author Paul Ferraro
 */
public interface SingleSignOnManager {
    /**
     * Creates a single sign-on entry using the specified mechanism and security identity
     * @param mechanismName an authentication mechanism name
     * @param identity a security identity of the authenticated user
     * @return a single sign-on entry
     */
    SingleSignOn create(String mechanismName, SecurityIdentity identity);

    /**
     * Locates the single sign-on entry with the specified identifier, or null if none exists.
     * @param id a single sign-on entry identifier
     * @return a single sign-on entry, or null if none was found
     */
    SingleSignOn find(String id);
}
