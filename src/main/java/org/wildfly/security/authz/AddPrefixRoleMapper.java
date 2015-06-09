/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2015 Red Hat, Inc., and individual contributors
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

import java.util.AbstractSet;
import java.util.Iterator;
import java.util.Set;

/**
 * A role mapper which adds a string prefix to the role name.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class AddPrefixRoleMapper implements RoleMapper {
    private final String prefix;

    /**
     * Construct a new instance.
     *
     * @param prefix the prefix to add to role names
     */
    public AddPrefixRoleMapper(final String prefix) {
        this.prefix = prefix;
    }

    public Set<String> mapRoles(final Set<String> rolesToMap) {
        return new AbstractSet<String>() {
            public Iterator<String> iterator() {
                final Iterator<String> iterator = rolesToMap.iterator();
                return new Iterator<String>() {
                    public boolean hasNext() {
                        return iterator.hasNext();
                    }

                    public String next() {
                        return prefix + iterator.next();
                    }
                };
            }

            public int size() {
                return rolesToMap.size();
            }

            public boolean contains(final Object o) {
                return o instanceof String && contains((String) o);
            }

            public boolean contains(final String s) {
                return s != null && s.startsWith(prefix) && rolesToMap.contains(s.substring(prefix.length()));
            }
        };
    }
}
