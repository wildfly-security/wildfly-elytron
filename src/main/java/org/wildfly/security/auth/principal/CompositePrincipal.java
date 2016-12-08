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

package org.wildfly.security.auth.principal;

import java.io.IOException;
import java.io.InvalidObjectException;
import java.io.ObjectInputStream;
import java.io.Serializable;
import java.security.Principal;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;

import org.wildfly.common.Assert;
import org.wildfly.security.util.ArrayIterator;

/**
 * A composite principal that consists of multiple elements of possibly disparate type.  This may be used to locate
 * a unique principal in a realm which is backed by a database that uses a composite key; in this case, the constituent
 * principals may be names or numbers, or a combination of both.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class CompositePrincipal implements Principal, Serializable, Iterable<Principal> {
    private static final long serialVersionUID = - 2610733957848661774L;
    private static final Principal[] NO_PRINCIPALS = new Principal[0];

    private final Principal[] p;

    /**
     * Construct a new instance.
     *
     * @param principals the collection of principals to use (must not be {@code null})
     */
    public CompositePrincipal(Collection<Principal> principals) {
        this(principals.toArray(NO_PRINCIPALS), false);
    }

    /**
     * Construct a new instance.
     *
     * @param principals the principals to use (must not be {@code null})
     */
    public CompositePrincipal(Principal... principals) {
        this(principals, true);
    }

    private CompositePrincipal(Principal[] principals, boolean clone) {
        p = principals.length == 0 ? NO_PRINCIPALS : clone ? principals.clone() : principals;
        for (int i = 0; i < p.length; i++) {
            Assert.checkNotNullArrayParam("principals", i, p[i]);
        }
    }

    /**
     * Get the principal name.
     *
     * @return the principal name, which is a string containing all of the nested principals
     */
    public String getName() {
        return Arrays.toString(p);
    }

    /**
     * Determine whether this composite principal contains the given nested principal.
     *
     * @param principal the nested principal (must not be {@code null})
     * @return {@code true} if this principal contains the nested principal, {@code false} otherwise
     */
    public boolean contains(final Principal principal) {
        Assert.checkNotNullParam("principal", principal);
        for (Principal test : p) {
            if (test.equals(principal)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Determine whether this composite principal contains the a nested principal of the given type class.
     *
     * @param type the nested principal type class (must not be {@code null})
     * @return {@code true} if this principal contains a nested principal of the given type, {@code false} otherwise
     */
    public boolean contains(final Class<? extends Principal> type) {
        Assert.checkNotNullParam("type", type);
        for (Principal test : p) {
            if (type.isInstance(test)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Get the number of nested principals.
     *
     * @return the number of nested principals
     */
    public int size() {
        return p.length;
    }

    /**
     * Get the principal at the given index.
     *
     * @param idx the index
     * @return the principal at the given index (not {@code null})
     * @throws IndexOutOfBoundsException if the given index is less than zero or greater than or equal to {@link #size()}
     */
    public Principal get(int idx) {
        try {
            return p[idx];
        } catch (ArrayIndexOutOfBoundsException e) {
            throw new IndexOutOfBoundsException();
        }
    }

    /**
     * Get the principal at the given index, if it is of the given type.
     *
     * @param idx the index
     * @param type the principal type class (must not be {@code null})
     * @param <P> the principal type
     * @return the principal at the given index or {@code null} if that principal is not of the given type
     * @throws IndexOutOfBoundsException if the given index is less than zero or greater than or equal to {@link #size()}
     */
    public <P extends Principal> P get(int idx, Class<P> type) {
        Assert.checkNotNullParam("type", type);
        final Principal item = get(idx);
        return type.isInstance(item) ? type.cast(item) : null;
    }

    /**
     * Get the first principal with the given type, if any.
     *
     * @param type the principal type class (must not be {@code null})
     * @param <P> the principal type
     * @return the first principal with the given type, or {@code null} if none was found
     * @throws IndexOutOfBoundsException if the given index is less than zero or greater than or equal to {@link #size()}
     */
    public <P extends Principal> P get(Class<P> type) {
        Assert.checkNotNullParam("type", type);
        for (Principal item : p) {
            if (type.isInstance(item)) type.cast(item);
        }
        return null;
    }

    /**
     * Get an iterator over this principal.
     *
     * @return an iterator over this principal (not {@code null})
     */
    public Iterator<Principal> iterator() {
        return new ArrayIterator<Principal>(p);
    }

    /**
     * Determine whether this principal is equal to the given object.
     *
     * @param obj the object
     * @return {@code true} if they are equal, {@code false} otherwise
     */
    public boolean equals(final Object obj) {
        return obj instanceof CompositePrincipal && equals((CompositePrincipal) obj);
    }

    /**
     * Determine whether this principal is equal to the given object.
     *
     * @param obj the object
     * @return {@code true} if they are equal, {@code false} otherwise
     */
    public boolean equals(final CompositePrincipal obj) {
        return obj == this || obj != null && Arrays.deepEquals(p, obj.p);
    }

    /**
     * Get the hash code of this principal.
     *
     * @return the hash code of this principal
     */
    public int hashCode() {
        return Arrays.deepHashCode(p);
    }

    /**
     * Get this principal as a string.
     *
     * @return this principal as a string (not {@code null})
     */
    public String toString() {
        return getName();
    }

    private void readObject(ObjectInputStream ois) throws IOException, ClassNotFoundException {
        ois.defaultReadObject();
        if (p == null) {
            throw new InvalidObjectException("Null principals array");
        }
        for (Principal principal : p) {
            if (principal == null) {
                throw new InvalidObjectException("Null principal array element");
            }
        }
    }
}
