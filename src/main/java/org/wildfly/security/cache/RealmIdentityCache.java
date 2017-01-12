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

import static org.wildfly.common.Assert.checkNotNullParam;

import java.security.Principal;
import java.util.function.Function;

import org.wildfly.security.auth.server.RealmIdentity;

/**
 * <p>Provides a mechanism to plug a cache for {@link RealmIdentity} instances obtained from a {@link org.wildfly.security.auth.server.SecurityRealm}.
 *
 * <p>Implementors should be aware that {@link RealmIdentity} instances may require serialization depending on the implementation in use, as well
 * any state within those instances such as attributes.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public interface RealmIdentityCache {

    /**
     * Puts a new {@link RealmIdentity} into the cache and referenced by the specified {@link Principal}.
     *
     * @param principal the {@link Principal} that references the realm identity being cached
     * @param realmIdentity the {@link RealmIdentity} instance
     */
    void put(Principal principal, RealmIdentity realmIdentity);

    /**
     * <p>If the specified key is not already associated with a value (or is mapped to {@code null}), attempts to compute its value using the given mapping
     * function and enters it into this map unless {@code null}.
     *
     * <p>If the function returns {@code null} no mapping is recorded. If
     * the function itself throws an (unchecked) exception, the
     * exception is rethrown, and no mapping is recorded.
     *
     * @param principal the {@link Principal} that references the realm identity being cached
     * @param mappingFunction the function that produces the {@link RealmIdentity} to cache or {@code null}
     * @return a cached {@link RealmIdentity} instance
     */
    default RealmIdentity computeIfAbsent(Principal principal, Function<Principal, RealmIdentity> mappingFunction) {
        checkNotNullParam("principal", principal);
        checkNotNullParam("mappingFunction", mappingFunction);
        RealmIdentity v;
        if ((v = get(principal)) == null) {
            RealmIdentity newValue;
            if ((newValue = mappingFunction.apply(principal)) != null) {
                put(principal, newValue);
                return newValue;
            }
        }
        return v;
    }

    /**
     * Obtains a previously cached {@link RealmIdentity} or {@code null} if no entry could be found with the specified {@link Principal}.
     *
     * @param principal the {@link Principal} that references a previously cached realm identity
     * @return a cached {@link RealmIdentity} instance or {@code null} if no entry could be found with the specified <code>principal</code>.
     */
    RealmIdentity get(Principal principal);

    /**
     * Removes a specific cached identity from the cache and referenced by the specified {@link Principal}.
     *
     * @param principal the {@link Principal} that references a previously cached realm identity
     */
    void remove(Principal principal);

    /**
     * Removes all cached identities from this cache.
     */
    void clear();
}
