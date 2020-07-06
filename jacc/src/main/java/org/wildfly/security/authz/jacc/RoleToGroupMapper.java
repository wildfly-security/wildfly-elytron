/*
 * Copyright 2020 Red Hat, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wildfly.security.authz.jacc;

import java.security.Principal;
import java.security.acl.Group;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;

import org.wildfly.security.auth.principal.NamePrincipal;
import org.wildfly.security.authz.Roles;

/**
 * A simple utility class to covert from an Elytron {@code Roles} representation to a Principal.
 *
 * This utility is only usable if the package "java.security.acl" is available.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class RoleToGroupMapper {

    static Collection<Principal> convert(Principal caller, Roles roles) {
        Collection<Principal> principals = new ArrayList<>();

        // add the 'Roles' group to the subject containing the identity's mapped roles.
        Group rolesGroup = new SimpleGroup("Roles");
        for (String role : roles) {
            rolesGroup.addMember(new NamePrincipal(role));
        }
        principals.add(rolesGroup);

        // add a 'CallerPrincipal' group containing the identity's principal.
        Group callerPrincipalGroup = new SimpleGroup("CallerPrincipal");
        callerPrincipalGroup.addMember(caller);
        principals.add(callerPrincipalGroup);

        return principals;
    }

    private static class SimpleGroup implements Group {

        private final String name;

        private final Set<Principal> principals;

        SimpleGroup(final String name) {
            this.name = name;
            this.principals = new HashSet<>();
        }

        @Override
        public String getName() {
            return this.name;
        }

        @Override
        public boolean addMember(Principal principal) {
            return this.principals.add(principal);
        }

        @Override
        public boolean removeMember(Principal principal) {
            return this.principals.remove(principal);
        }

        @Override
        public Enumeration<? extends Principal> members() {
            return Collections.enumeration(this.principals);
        }

        @Override
        public boolean isMember(Principal principal) {
            return this.principals.contains(principal);
        }
    }

}
