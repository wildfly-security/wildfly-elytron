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

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import java.net.URL;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import org.junit.Test;

/**
 * @author <a href="mailto:pesilva@redhat.com">Pedro Hos</a>
 *
 */
public class PropertiesMappedRoleMapperTest {

    @Test
    public void testPropertiesRoleMapperWithMappedRole() {
        Roles roles = createRoles("joe", "admin", "enterprise-role");
        URL resource = getClass().getResource("rolesMapping-roles.properties");
        PropertiesMappedRoleMapper mapper = new PropertiesMappedRoleMapper.Builder().rootPath(resource.getPath()).build();
        Roles mapRoles = mapper.mapRoles(roles);

        assertTrue(mapRoles.contains("role-1"));
        assertTrue(mapRoles.contains("role-abc"));
        assertTrue(mapRoles.contains("enterprise-role"));
        assertTrue(mapRoles.contains("admin"));
        assertTrue(mapRoles.contains("joe"));

    }

    @Test
    public void testPropertiesRoleMapperWithoutMappedRole() {
        Roles roles = createRoles("joe", "admin");
        URL resource = getClass().getResource("rolesMapping-roles.properties");
        PropertiesMappedRoleMapper mapper = new PropertiesMappedRoleMapper.Builder().rootPath(resource.getPath()).build();
        Roles mapRoles = mapper.mapRoles(roles);

        assertTrue(mapRoles.contains("admin"));
        assertTrue(mapRoles.contains("joe"));
        assertFalse(mapRoles.contains("role-1"));
        assertFalse(mapRoles.contains("role-abc"));
        assertFalse(mapRoles.contains("enterprise-role"));

    }

    @Test
    public void testPropertiesRoleMapperWrongPropertiesPath() {
        Roles roles = createRoles("joe", "admin");
        URL resource = getClass().getResource("rolesMapping-roles.properties");
        PropertiesMappedRoleMapper mapper = new PropertiesMappedRoleMapper.Builder().rootPath(resource.getPath() + "-wrong").build();

        Exception exception = assertThrows(IllegalStateException.class, () -> {
            mapper.mapRoles(roles);
        });

        String actualMessage = exception.getMessage();
        assertTrue(actualMessage.equals("ELY16006: Can not read the provided properties file."));

    }

    private Roles createRoles(String... roles) {
        return Roles.fromSet(createSet(roles));
    }

    private Set<String> createSet(String... values) {
        HashSet<String> set = new HashSet<>();
        Collections.addAll(set, values);
        return set;
    }
}
