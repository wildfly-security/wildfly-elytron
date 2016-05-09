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
package org.wildfly.security.authz;

import static org.wildfly.security._private.ElytronMessages.log;
import static org.wildfly.common.Assert.checkNotNullParam;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.wildfly.security.permission.PermissionVerifier;

/**
 * A simple {@link PermissionMapper} implementation that maps to pre-defined {@link PermissionVerifier} instances.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class SimplePermissionMapper implements PermissionMapper {

    private final MappingMode mappingMode;

    private final List<Mapping> mappings;

    private SimplePermissionMapper(MappingMode mappingMode, List<Mapping> mappings) {
        this.mappingMode = mappingMode;
        this.mappings = mappings;
    }

    @Override
    public PermissionVerifier mapPermissions(PermissionMappable permissionMappable, Roles roles) {
        checkNotNullParam("permissionMappable", permissionMappable);
        checkNotNullParam("roles", roles);

        PermissionVerifier result = null;

        for (Mapping current : mappings) {
            if (current.principals.contains(permissionMappable.getPrincipal().getName()) || roles.containsAny(current.roles)) {
                    switch (mappingMode) {
                        case FIRST_MATCH:
                            return current.permissionVerifer;
                        case AND:
                            result = result != null ? result.and(current.permissionVerifer) : current.permissionVerifer;
                            break;
                        case OR:
                            result = result != null ? result.or(current.permissionVerifer) : current.permissionVerifer;
                            break;
                        case UNLESS:
                            result = result != null ? result.unless(current.permissionVerifer) : current.permissionVerifer;
                            break;
                        case XOR:
                            result = result != null ? result.xor(current.permissionVerifer) : current.permissionVerifer;
                            break;
                }
            }
        }


        return result != null ? result : PermissionVerifier.NONE;
    }

    /**
     * Construct a new {@link Builder} for creating the {@link PermissionMapper}.
     *
     * @return a new {@link Builder} for creating the {@link PermissionMapper}.
     */
    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {

        private boolean built = false;

        private MappingMode mappingMode;

        private final List<Mapping> mappings = new ArrayList<>();

        Builder() {
        }

        /**
         * Set the mapping mode that the newly created {@link PermissionMapper} should use.
         *
         * @param mappingMode the mapping mode.
         * @return {@code this} builder to allow chaining.
         */
        public Builder setMappingMode(MappingMode mappingMode) {
            assertNotBuilt();
            this.mappingMode = mappingMode;

            return this;
        }

        /**
         * Add a new mapping to a {@link PermissionVerifier}, if the {@link PermissionMappable} being mapped has a principal name that is in the {@link Set} of principals or of any of the assigned roles are matched this mapping will be a match.
         *
         * @param principals the principal names to compare with the {@link PermissionMappable} principal.
         * @param roles the role names to compare with the roles being passed for mapping.
         * @param permissionVerifer the {@link PermissionVerifier} to use in the event of a resulting match.
         * @return {@code this} builder to allow chaining.
         */
        public Builder addMapping(Set<String> principals, Set<String> roles, PermissionVerifier permissionVerifer) {
            assertNotBuilt();
            mappings.add(new Mapping(principals, roles, permissionVerifer));

            return this;
        }

        /**
         * Build and return the resulting {@link PermissionMapper}.
         *
         * @return the resulting {@link PermissionMapper}
         */
        public PermissionMapper build() {
            assertNotBuilt();
            built = true;

            return new SimplePermissionMapper(mappingMode, mappings);
        }

        private void assertNotBuilt() {
            if (built) {
                throw log.builderAlreadyBuilt();
            }
        }
    }

    private static class Mapping {

        private final Set<String> principals;

        private final Set<String> roles;

        private final PermissionVerifier permissionVerifer;

        private Mapping(Set<String> principals, Set<String> roles, PermissionVerifier permissionVerifer) {
            this.principals = new HashSet<>(checkNotNullParam("principals", principals));
            this.roles = Collections.unmodifiableSet(new HashSet<>(checkNotNullParam("roles", roles)));
            this.permissionVerifer = checkNotNullParam("permissionVerifier", permissionVerifer);
        }

    }

    public enum MappingMode {

        /**
         * If multiple mappings are found only the first will be used.
         */
        FIRST_MATCH,

        /**
         * If multiple mappings are found the corresponding {@link PermissionVerifier} instances will be combined using 'and'.
         */
        AND,

        /**
         * If multiple mappings are found the corresponding {@link PermissionVerifier} instances will be combined using 'or'.
         */
        OR,

        /**
         * If multiple mappings are found the corresponding {@link PermissionVerifier} instances will be combined using 'xor'.
         */
        XOR,

        /**
         * If multiple mappings are found the corresponding {@link PermissionVerifier} instances will be combined using 'unless'.
         */
        UNLESS;
    }

}
