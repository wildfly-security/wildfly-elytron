/*
 * JBoss, Home of Professional Open Source
 *
 * Copyright 2013 Red Hat, Inc. and/or its affiliates.
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

import java.util.Set;

import org.wildfly.common.Assert;

/**
 * A role mapper is responsible for mapping roles based on their raw form.
 * <p>
 * Roles are basically represented as {@link String} values, where these values are their names. Role mapping allows to transform roles
 * from their raw form (eg.: just like they were loaded from a identity store such as a database or LDAP server) in a more consistent
 * form.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public interface RoleMapper {

    /**
     * Returns a set of strings representing the roles mapped from the given roles in their raw form.
     *
     * @param rolesToMap the roles in their raw form to apply mapping
     * @return the mapped role set
     */
    Set<String> mapRoles(Set<String> rolesToMap);

    /**
     * A default implementation that does nothing but return the given roles.
     */
    RoleMapper IDENTITY_ROLE_MAPPER = rolesToMap -> rolesToMap;

    /**
     * Create a role mapper which is the intersection (logical "and") of the results of this and the given role mapper.
     *
     * @param other the other role mapper
     * @return the intersection role mapper
     */
    default RoleMapper and(RoleMapper other) {
        RoleMapper left = this;
        return rolesToMap -> new IntersectionSet(left.mapRoles(rolesToMap), other.mapRoles(rolesToMap));
    }

    /**
     * Create a role mapper which is the union (logical "or") of the results of this and the given role mapper.
     *
     * @param other the other role mapper
     * @return the union role mapper
     */
    default RoleMapper or(RoleMapper other) {
        RoleMapper left = this;
        return rolesToMap -> new UnionSet(left.mapRoles(rolesToMap), other.mapRoles(rolesToMap));
    }

    /**
     * Create a role mapper which is the symmetric difference (logical "xor") of the results of this and the given role mapper.
     *
     * @param other the other role mapper
     * @return the difference role mapper
     */
    default RoleMapper xor(RoleMapper other) {
        RoleMapper left = this;
        return rolesToMap -> new DifferenceSet(left.mapRoles(rolesToMap), other.mapRoles(rolesToMap));
    }

    /**
     * Create an aggregate role mapper.  Each role mapper is applied in order.
     *
     * @param mapper1 the first role mapper to apply (must not be {@code null})
     * @param mapper2 the second role mapper to apply (must not be {@code null})
     * @return the aggregate role mapper (not {@code null})
     */
    static RoleMapper aggregate(RoleMapper mapper1, RoleMapper mapper2) {
        Assert.checkNotNullParam("mapper1", mapper1);
        Assert.checkNotNullParam("mapper2", mapper2);
        return rolesToMap -> mapper2.mapRoles(mapper1.mapRoles(rolesToMap));
    }

    /**
     * Create an aggregate role mapper.  Each role mapper is applied in order.
     *
     * @param mappers the role mappers to apply (most not be {@code null} or contain {@code null} elements)
     * @return the aggregate role mapper (not {@code null})
     */
    static RoleMapper aggregate(RoleMapper... mappers) {
        Assert.checkNotNullParam("mappers", mappers);
        final RoleMapper[] clone = mappers.clone();
        for (int i = 0; i < clone.length; i++) {
            Assert.checkNotNullArrayParam("mappers", i, clone[i]);
        }
        return (rolesToMap) -> {
            for (RoleMapper r : clone) rolesToMap = r.mapRoles(rolesToMap);
            return rolesToMap;
        };
    }
}
