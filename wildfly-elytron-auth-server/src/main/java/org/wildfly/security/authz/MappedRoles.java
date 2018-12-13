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

import java.util.Iterator;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Set;


class MappedRoles implements Roles {
    private final Roles delegate;
    private final Map<String, Set<String>> reverseRoleMap;

    public MappedRoles(final Roles delegate, final Map<String, Set<String>> reverseRoleMap) {
        this.delegate = delegate;
        this.reverseRoleMap = reverseRoleMap;
    }

    @Override
    public boolean contains(String roleName) {
        Set<String> rolesToContain = reverseRoleMap.get(roleName);
        if (rolesToContain == null) return false;
        return delegate.containsAny(rolesToContain);
    }

    @Override
    public Iterator<String> iterator() {
        final Iterator<String> iterator = reverseRoleMap.keySet().iterator();

        return new Iterator<String>() {
            String next = null;

            @Override
            public boolean hasNext() {
                if (next != null) return true;

                while (iterator.hasNext()) {
                    String nextt = iterator.next();
                    if (delegate.containsAny(reverseRoleMap.get(nextt))) {
                        next = nextt;
                        return true;
                    }
                }

                return false;
            }

            @Override
            public String next() {
                if (! hasNext()) {
                    throw new NoSuchElementException();
                }
                final String next = this.next;
                this.next = null;
                return next;
            }
        };
    }
}
