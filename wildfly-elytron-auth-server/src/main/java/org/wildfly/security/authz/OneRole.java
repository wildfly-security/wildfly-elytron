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
import java.util.Spliterator;
import java.util.Spliterators;

import org.wildfly.security.util.EnumerationIterator;

final class OneRole implements Roles {
    private final String role;

    OneRole(final String role) {
        this.role = role;
    }

    public boolean contains(final String roleName) {
        return role.equals(roleName);
    }

    public boolean isEmpty() {
        return false;
    }

    public Spliterator<String> spliterator() {
        return Spliterators.spliterator(iterator(), 1, Spliterator.NONNULL | Spliterator.DISTINCT | Spliterator.SIZED);
    }

    public Roles and(final Roles other) {
        return other.contains(role) ? this : NONE;
    }

    public Roles or(final Roles other) {
        return other.contains(role) ? other : Roles.super.or(other);
    }

    public Roles minus(final Roles other) {
        return other.contains(role) ? NONE : this;
    }

    public Roles addSuffix(final String suffix) {
        return new OneRole(role + suffix);
    }

    public Roles addPrefix(final String prefix) {
        return new OneRole(prefix + role);
    }

    public Iterator<String> iterator() {
        return EnumerationIterator.over(role);
    }
}
