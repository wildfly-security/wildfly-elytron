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

package org.wildfly.security.auth.server;

import java.security.Principal;

import org.wildfly.common.Assert;
import org.wildfly.security.evidence.Evidence;

/**
 * A realm mapper.  Examines authentication identity information and translates it into a realm name.  If the realm
 * mapper does not recognize the authentication information, a default realm will be chosen.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
@FunctionalInterface
public interface RealmMapper {

    /**
     * Get the realm mapping.  Return {@code null} if the default realm should be used.
     *
     * @param name the user name (or {@code null} if none is known for this authentication)
     * @param principal the authentication principal (or {@code null} if none is known for this authentication)
     * @param evidence the authentication evidence (or {@code null} if none is known for this authentication)
     * @return the realm, or {@code null} if no particular realm matches the authentication information
     */
    String getRealmMapping(String name, Principal principal, Evidence evidence);

    /**
     * A realm mapper which always falls back to a default realm.
     */
    RealmMapper DEFAULT_REALM_MAPPER = single(null);

    /**
     * Create a realm mapper that always maps to the given realm.
     *
     * @param realmName the realm name to return, or {@code null} if the default realm should be used
     * @return the realm mapper returning {@code realmName}
     */
    static RealmMapper single(String realmName) {
        return (name, principal, evidence) -> realmName;
    }

    /**
     * Create an aggregate realm mapping strategy.
     *
     * @param mapper1 the first mapper to try (must not be {@code null})
     * @param mapper2 the second mapper to try (must not be {@code null})
     * @return an aggregated mapper (not {@code null})
     */
    static RealmMapper aggregate(RealmMapper mapper1, RealmMapper mapper2) {
        Assert.checkNotNullParam("mapper1", mapper1);
        Assert.checkNotNullParam("mapper2", mapper2);
        return (name, principal, evidence) -> {
            String mapping = mapper1.getRealmMapping(name, principal, evidence);
            if (mapping == null) mapping = mapper2.getRealmMapping(name, principal, evidence);
            return mapping;
        };
    }

    /**
     * Create an aggregate realm mapping strategy.
     *
     * @param mappers the mappers to try (must not be {@code null})
     * @return an aggregated mapper (not {@code null})
     */
    static RealmMapper aggregate(RealmMapper... mappers) {
        Assert.checkNotNullParam("mappers", mappers);
        return (name, principal, evidence) -> {
            for (RealmMapper mapper : mappers) if (mapper != null) {
                String mapping = mapper.getRealmMapping(name, principal, evidence);
                if (mapping != null) return mapping;
            }
            return null;
        };
    }
}
