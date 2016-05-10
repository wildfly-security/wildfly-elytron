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

import static org.wildfly.common.Assert.checkNotNullParam;
import static org.wildfly.common.Assert.checkNotEmptyParam;
import java.util.Collections;
import java.util.Iterator;
import java.util.Set;
import java.util.Spliterator;
import java.util.Spliterators;
import java.util.function.Consumer;

import org.wildfly.common.Assert;

/**
 * A collection of roles.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public interface Roles extends Iterable<String> {

    /**
     * Determine if this collection contains the given role name.
     *
     * @param roleName the role name
     * @return {@code true} if the role is contained in this collection, {@code false} otherwise
     */
    boolean contains(String roleName);

    /**
     * Determine if this collection contains any of the given role names.
     *
     * @param desiredRoles the roles to check.
     * @return {@code true} if this collection contains any of the desired roles, {@code false} otherwise.
     */
    default boolean containsAny(Set<String> desiredRoles) {
        checkNotNullParam("desiredRoles", desiredRoles);
        for (String current : desiredRoles) {
            if (contains(current)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Determine if this collection contains all of the given role names.
     *
     * @param desiredRoles the roles to check.
     * @return {@code true} if this collection contains all of the desired roles, {@code false} otherwise.
     */
    default boolean containsAll(Set<String> desiredRoles) {
        checkNotNullParam("desiredRoles", desiredRoles);
        checkNotEmptyParam("desiredRoles", desiredRoles);
        for (String current : desiredRoles) {
            if (contains(current) == false) {
                return false;
            }
        }

        return true;
    }

    /**
     * Determine whether this roles collection is empty.
     *
     * @return {@code true} if the collection is empty, {@code false} otherwise
     */
    default boolean isEmpty() {
        return ! iterator().hasNext();
    }

    /**
     * Create a {@link Spliterator} over this roles collection.
     *
     * @return the spliterator (not {@code null})
     */
    default Spliterator<String> spliterator() {
        return Spliterators.spliteratorUnknownSize(iterator(), Spliterator.NONNULL | Spliterator.DISTINCT);
    }

    /**
     * Construct a new roles collection from a set.
     *
     * @param set the set of role names (must not be {@code null})
     * @return the roles collection (not {@code null})
     */
    static Roles fromSet(Set<String> set) {
        Assert.checkNotNullParam("set", set);
        if (set instanceof Roles) {
            return (Roles) set;
        }
        return new Roles() {
            public boolean contains(final String roleName) {
                return set.contains(roleName);
            }

            public Iterator<String> iterator() {
                return set.iterator();
            }

            public Spliterator<String> spliterator() {
                return set.spliterator();
            }

            public void forEach(final Consumer<? super String> action) {
                set.forEach(action);
            }

            public boolean isEmpty() {
                return set.isEmpty();
            }
        };
    }

    /**
     * Construct a role set consisting of a single role.
     *
     * @param role the role name (must not be {@code null})
     * @return the role set (not {@code null})
     */
    static Roles of(String role) {
        Assert.checkNotNullParam("role", role);
        return new OneRole(role);
    }

    /**
     * Get the intersection of this collection and another.
     *
     * @param other the other roles collection (must not be {@code null})
     * @return the intersection (not {@code null})
     */
    default Roles and(Roles other) {
        Assert.checkNotNullParam("other", other);
        return isEmpty() || other.isEmpty() ? NONE : new IntersectionRoles(this, other);
    }

    /**
     * Get the union of this collection and another.
     *
     * @param other the other roles collection (must not be {@code null})
     * @return the union (not {@code null})
     */
    default Roles or(Roles other) {
        Assert.checkNotNullParam("other", other);
        return isEmpty() ? other : other.isEmpty() ? this : new UnionRoles(this, other);
    }

    /**
     * Get the disjunction of this collection and another.
     *
     * @param other the other roles collection (must not be {@code null})
     * @return the disjunction (not {@code null})
     */
    default Roles xor(Roles other) {
        Assert.checkNotNullParam("other", other);
        return isEmpty() ? other : other.isEmpty() ? this : new DisjunctionRoles(this, other);
    }

    /**
     * Get a roles collection which consists of the roles in this collection minus the roles in the other collection.
     *
     * @param other the other collection (must not be {@code null})
     * @return the difference (not {@code null})
     */
    default Roles minus(Roles other) {
        Assert.checkNotNullParam("other", other);
        return isEmpty() ? NONE : other.isEmpty() ? this : new DifferenceRoles(this, other);
    }

    /**
     * Get a roles collection which adds a suffix to all role names.
     *
     * @param suffix the suffix to add (must not be {@code null})
     * @return the new roles collection (not {@code null})
     */
    default Roles addSuffix(String suffix) {
        Assert.checkNotNullParam("suffix", suffix);
        return suffix.isEmpty() ? this : isEmpty() ? NONE : new AddSuffixRoles(this, suffix);
    }

    /**
     * Get a roles collection which adds a prefix to all role names.
     *
     * @param prefix the prefix to add (must not be {@code null})
     * @return the new roles collection (not {@code null})
     */
    default Roles addPrefix(String prefix) {
        Assert.checkNotNullParam("prefix", prefix);
        return prefix.isEmpty() ? this : isEmpty() ? NONE : new AddPrefixRoles(this, prefix);
    }

    /**
     * The empty roles collection.
     */
    Roles NONE = new Roles() {
        public boolean contains(final String roleName) {
            return false;
        }

        public Iterator<String> iterator() {
            return Collections.emptyIterator();
        }

        public Spliterator<String> spliterator() {
            return Spliterators.emptySpliterator();
        }

        public Roles and(final Roles other) {
            return this;
        }

        public Roles or(final Roles other) {
            return other;
        }

        public Roles xor(final Roles other) {
            return other;
        }

        public Roles minus(final Roles other) {
            return this;
        }

        public Roles addSuffix(final String suffix) {
            return this;
        }

        public Roles addPrefix(final String prefix) {
            return this;
        }

        public boolean isEmpty() {
            return true;
        }
    };
}
