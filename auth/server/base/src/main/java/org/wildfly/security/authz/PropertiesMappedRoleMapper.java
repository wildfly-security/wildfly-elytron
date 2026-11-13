/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2025 Red Hat, Inc., and individual contributors
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

import static org.wildfly.common.Assert.checkNotNullParam;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

import org.wildfly.security.auth.server._private.ElytronMessages;

/**
 * A Property Role Mapper.
 * <p>
 * The Property Role Mapper allows mapping application roles present on a properties file with the content like: ROLE=APPLICATION_ROLE1,APPLICATION_ROLE2
 * <p>
 * The properties file is read once, when the mapper is built; later changes to the file are not picked up.
 *
 * @author <a href="mailto:pesilva@redhat.com">Pedro Hos</a>
 *
 */
public class PropertiesMappedRoleMapper implements RoleMapper {

    private final Map<String, Set<String>> roleMappings;

    public PropertiesMappedRoleMapper(Builder builder) {
        checkNotNullParam("rootPath", builder.rootPath);
        this.roleMappings = loadMappings(builder.rootPath);
    }

    @Override
    public Roles mapRoles(Roles rolesToMap) {
        Set<String> rolesToAdd = new HashSet<>();

        for (Map.Entry<String, Set<String>> entry : roleMappings.entrySet()) {
            if (rolesToMap.contains(entry.getKey())) {
                rolesToAdd.addAll(entry.getValue());
            }
        }

        if (rolesToAdd.isEmpty()) {
            return rolesToMap;
        }

        return rolesToMap.or(Roles.fromSet(rolesToAdd));
    }

    private static Map<String, Set<String>> loadMappings(String roleProperties) {
        Properties prop = new Properties();
        try (InputStream input = new FileInputStream(roleProperties)) {
            prop.load(input);
        } catch (IOException ioex) {
            throw ElytronMessages.log.cantReadPropertiesFile(ioex);
        }

        Map<String, Set<String>> mappings = new HashMap<>();
        for (String key : prop.stringPropertyNames()) {
            Set<String> roles = new HashSet<>();
            for (String role : prop.getProperty(key).trim().split("\\s*,\\s*")) {
                if (!role.isEmpty()) {
                    roles.add(role);
                }
            }
            if (!roles.isEmpty()) {
                mappings.computeIfAbsent(key.trim(), k -> new HashSet<>()).addAll(roles);
            }
        }

        Map<String, Set<String>> result = new HashMap<>();
        mappings.forEach((k, v) -> result.put(k, Collections.unmodifiableSet(v)));
        return Collections.unmodifiableMap(result);
    }

    /**
     * Construct a new {@link Builder} for creating the {@link PropertiesMappedRoleMapper}.
     *
     * @return a new {@link Builder} for creating the {@link PropertiesMappedRoleMapper}.
     */
    public static class Builder {

        private String rootPath;

        public PropertiesMappedRoleMapper build() {
            return new PropertiesMappedRoleMapper(this);
        }

        /**
         * Set the path of the properties file containing the role mappings.
         *
         * @param rootPath the path of the properties file (must not be {@code null})
         * @return this builder
         */
        public Builder rootPath(String rootPath) {
            checkNotNullParam("rootPath", rootPath);
            this.rootPath = rootPath;
            return this;
        }

    }
}
