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
import java.util.HashSet;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.stream.Collectors;

import org.wildfly.security.auth.server._private.ElytronMessages;

/**
 * A Property Role Mapper.
 * <p>
 * The Property Roler Mapper allows mapping application roles present on a properties file with the content like: ROLE=APPLICATION_ROLE1,APPLICATION_ROLE2
 *
 * @author <a href="mailto:pesilva@redhat.com">Pedro Hos</a>
 *
 */
public class PropertiesMappedRoleMapper implements RoleMapper {

    private String rootPath;

    public PropertiesMappedRoleMapper(Builder builder) {
        checkNotNullParam("rootPath", builder.rootPath);
        this.rootPath = builder.rootPath;
    }

    @Override
    public Roles mapRoles(Roles rolesToMap) {
        Set<String> rolesToAdd = new HashSet<String>();
        Set<Map.Entry<String, String>> propertiesMap = getPropertiesMap(rootPath);

        for(Map.Entry<String,String> entry: propertiesMap) {
            if (rolesToMap.contains(entry.getKey().trim())) {
                for(String role: entry.getValue().trim().split(",")) {
                    rolesToAdd.add(role);
                }
            }
        }

        if (rolesToAdd.size() == 0) {
            return rolesToMap;
        }

        return rolesToMap.or(Roles.fromSet(rolesToAdd));
    }

    private Set<Map.Entry<String, String>> getPropertiesMap(String roleProperties) {

        Properties prop = new Properties();
        InputStream input = null;

        try {
            input = new FileInputStream(roleProperties);
            prop.load(input);

            Set<Map.Entry<String, String>> entries = prop.entrySet().stream()
                    .collect(Collectors.toMap(e -> (String) e.getKey(), e -> (String) e.getValue())).entrySet();

            return entries;

        } catch (IOException ioex) {
            throw ElytronMessages.log.cantReadPropertiesFile(ioex);
        } finally {
            if (input != null) {
                try {
                    input.close();
                } catch (IOException e) {
                    throw ElytronMessages.log.cantClosePropertiesFile(e);
                }
            }
        }
    }

    /**
     * Construct a new {@link Builder} for creating the {@link PropertiesMappedRoleMapperTest}.
     *
     * @return a new {@link Builder} for creating the {@link PropertiesMappedRoleMapperTest}.
     */
    public static class Builder {

        private String rootPath;

        public PropertiesMappedRoleMapper build() {
            return new PropertiesMappedRoleMapper(this);
        }

        /**
         *
         * @param rootPath
         * @return
         */
        public Builder rootPath(String rootPath) {
            checkNotNullParam("rootPath", rootPath);
            this.rootPath = rootPath;
            return this;
        }

    }
}
