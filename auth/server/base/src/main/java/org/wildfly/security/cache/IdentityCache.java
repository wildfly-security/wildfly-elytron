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

package org.wildfly.security.cache;

import org.wildfly.security.auth.server.SecurityIdentity;

/**
 * <p>An identity cache is responsible to provide a specific caching strategy for identities. It should be used in conjunction with
 * {@link org.wildfly.security.auth.callback.CachedIdentityAuthorizeCallback} when performing authorization within a authentication mechanism.
 *
 * <p>Implementations of this interface are specific for each authentication mechanism.</p>
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 * @see org.wildfly.security.auth.callback.CachedIdentityAuthorizeCallback
 */
public interface IdentityCache {

    /**
     * Puts a {@link SecurityIdentity} into the cache.
     *
     * @param identity the identity to cache (not {@code null})
     */
    void put(SecurityIdentity identity);

    /**
     * Returns an identity previously cached.
     *
     * @return the cached identity or {@code null} if there is no identity in the cache
     */
    CachedIdentity get();

    /**
     * Removes an identity from the cache.
     *
     * @return the cached identity or {@code null} if there is no identity in the cache
     */
    CachedIdentity remove();
}
