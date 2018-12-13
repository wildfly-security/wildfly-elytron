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

import java.util.Iterator;

class AddSuffixRoles implements Roles {
    private final Roles delegate;
    private final String suffix;

    AddSuffixRoles(final Roles delegate, final String suffix) {
        this.delegate = delegate;
        this.suffix = suffix;
    }

    public boolean contains(final String roleName) {
        final String suffix = this.suffix;
        return roleName.endsWith(suffix) && delegate.contains(roleName.substring(0, roleName.length() - suffix.length()));
    }

    public Iterator<String> iterator() {
        final Iterator<String> iterator = delegate.iterator();
        return new Iterator<String>() {
            public boolean hasNext() {
                return iterator.hasNext();
            }

            public String next() {
                return iterator.next() + suffix;
            }
        };
    }
}
