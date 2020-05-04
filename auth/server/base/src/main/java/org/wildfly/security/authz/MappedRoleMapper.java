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
package org.wildfly.security.authz;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import static org.wildfly.security.auth.server._private.ElytronMessages.log;

/**
 * A simple mapping role mapper.
 *
 * Maps each role to a set of new roles using a String to Set<String> map.
 *
 * @author <a href="mailto:mmazanek@redhat.com">Martin Mazanek</a>
 */
public class MappedRoleMapper implements RoleMapper {

    private final Map<String, Set<String>> reverseRoleMap = new LinkedHashMap<>();;
    private volatile boolean initialized = false;

    /**
     * Construct a new instance.
     * Called from WildFly core when using this as a custom component. You should not use this constructor and use {@link MappedRoleMapper.Builder} instead.
     * You must call {@link #initialize(Map)} to configure mapping map before usage.
     *
     * @see MappedRoleMapper.Builder
     */
    public MappedRoleMapper() {}


    private MappedRoleMapper(Map<String, Set<String>> roleMap) {
        Set<Map.Entry<String, Set<String>>> entrySet = roleMap.entrySet();

        for (Map.Entry<String, Set<String>> entry : entrySet) {

            for (String mappedRole : entry.getValue()) {
                Set<String> rolesToMappedRole = reverseRoleMap.get(mappedRole);

                if (rolesToMappedRole == null) {
                    rolesToMappedRole = new LinkedHashSet<>();
                    reverseRoleMap.put(mappedRole, rolesToMappedRole);
                }

                rolesToMappedRole.add(entry.getKey());
            }
        }

        initialized = true;
    }

    /**
     * Custom component method.
     * Called from WildFly core. Used to include mapped role mapping functionality in older WildFly versions.
     *
     * @param configuration map of mapping rules where key is delegate role and value is whitespace separated list of new roles
     * @throws IllegalStateException when called mapper is already initialized
     */
    public void initialize(final Map<String, String> configuration) {
        if (initialized) {
            throw log.roleMappedAlreadyInitialized();
        }
        reverseRoleMap.clear();
        configuration.forEach( (key, value) -> {
            String[] newRoles = value.split("\\s+");
            for (String newRole : newRoles) {
                Set<String> rolesToMappedRole = reverseRoleMap.get(newRole);
                if (rolesToMappedRole == null) {
                    rolesToMappedRole = new LinkedHashSet<>();
                    reverseRoleMap.put(newRole, rolesToMappedRole);
                }
                rolesToMappedRole.add(key);
            }
        });
        initialized = true;
    }

    @Override
    public Roles mapRoles(Roles rolesToMap) {
        if (!initialized) {
            throw log.roleMappedNotInitialized();
        }
        return new MappedRoles(rolesToMap, this.reverseRoleMap);
    }

    /**
     * Construct a new {@link Builder} for creating the {@link MappedRoleMapper}.
     *
     * @return a new {@link Builder} for creating the {@link MappedRoleMapper}.
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * A builder for map backed role mappers.
     */
    public static class Builder {
        private Map<String, Set<String>> roleMap;

        Builder() {
        }

        /**
         * Build and return the resulting {@link MappedRoleMapper}.
         *
         * @return the resulting {@link MappedRoleMapper}
         */
        public MappedRoleMapper build() {
            return new MappedRoleMapper(roleMap);
        }

        /**
         * Set the {@link Map} to use for mapping roles
         *
         * @param roleMap the role map
         * @return {@code this} builder to allow chaining.
         */
        public Builder setRoleMap(Map<String, Set<String>> roleMap) {
            this.roleMap = roleMap;
            return this;
        }
    }
}
