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

package org.wildfly.security.auth.realm;

import java.security.Principal;
import java.util.function.Consumer;

import org.wildfly.security.auth.server.SecurityRealm;

/**
 * This interface defines a contract for a {@link SecurityRealm} that supports caching of {@link org.wildfly.security.auth.server.RealmIdentity} instances.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 * @see CachingSecurityRealm
 */
public interface CacheableSecurityRealm extends SecurityRealm {

    /**
     * Register a listener that should be invoked by this realm in order to notify the caching layer about changes to a specific identity.
     *
     * @param listener the listener
     */
    void registerIdentityChangeListener(Consumer<Principal> listener);
}
