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

/**
 * <p>A role mapper is responsible for mapping roles based on their raw form.<p>
 *
 * <p>Roles are basically represented as {@link String} values, where these values are their names. Role mapping allows to transform roles
 * from their raw form (eg.: just like they were loaded from a identity store such as a database or LDAP server) in a more consistent
 * form.</p>
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public interface RoleMapper {

    /**
     * <p>
     *     Returns a set of strings representing the roles mapped from the given roles in their raw form.
     * </p>
     *
     * @param rolesToMap the roles in their raw form to apply mapping.
     * @return
     */
    Set<String> mapRoles(Set<String> rolesToMap);

    /**
     * <p>A default implementation that does nothing but return the given roles.</p>
     */
    RoleMapper IDENTITY_ROLE_MAPPER = rolesToMap -> rolesToMap;
}
