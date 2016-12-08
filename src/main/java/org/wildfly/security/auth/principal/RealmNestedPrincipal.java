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

import org.wildfly.common.Assert;

/**
 * A principal type which is used to find a specific identity in a specific realm.  This principal can be used to locate
 * an exact identity whose name may have changed or may be unknown, but which can be located another way (for example,
 * by primary key).
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class RealmNestedPrincipal implements Principal, Serializable {
    private static final long serialVersionUID = 3776427564561628331L;

    // names are short to facilitate serialization
    /**
     * @serial the realm name (must not be {@code null})
     */
    private final String r;
    /**
     * @serial the nested principal (must not be {@code null})
     */
    private final Principal p;

    /**
     * Construct a new instance.
     *
     * @param realmName the realm name (must not be {@code null})
     * @param nestedPrincipal the nested principal (must not be {@code null})
     */
    public RealmNestedPrincipal(final String realmName, final Principal nestedPrincipal) {
        Assert.checkNotNullParam("realmName", realmName);
        Assert.checkNotNullParam("nestedPrincipal", nestedPrincipal);
        this.r = realmName;
        this.p = nestedPrincipal;
    }

    /**
     * Get the realm name.
     *
     * @return the realm name (not {@code null})
     */
    public String getRealmName() {
        return r;
    }

    /**
     * Get the nested principal.
     *
     * @return the nested principal (not {@code null})
     */
    public Principal getNestedPrincipal() {
        return p;
    }

    /**
     * Get the nested principal if it is of the given type class.
     *
     * @return the nested principal, or {@code null} if the nested principal is not of the given type
     */
    public <P extends Principal> P getNestedPrincipal(Class<P> principalClass) {
        return principalClass.isInstance(p) ? principalClass.cast(p) : null;
    }

    /**
     * Returns the name of this principal, which is composed of the realm name and the name of the nested principal.
     *
     * @return the name of this principal
     */
    public String getName() {
        return r + "/" + p.getName();
    }

    /**
     * Get the hash code of this principal.
     *
     * @return the hash code of this principal
     */
    public int hashCode() {
        return r.hashCode() * 17 + p.hashCode();
    }

    /**
     * Determine whether this principal is equal to the given object.
     *
     * @param obj the object
     * @return {@code true} if they are equal, {@code false} otherwise
     */
    public boolean equals(final Object obj) {
        return obj instanceof RealmNestedPrincipal && equals((RealmNestedPrincipal) obj);
    }

    /**
     * Determine whether this principal is equal to the given object.
     *
     * @param obj the object
     * @return {@code true} if they are equal, {@code false} otherwise
     */
    public boolean equals(final RealmNestedPrincipal obj) {
        return this == obj || obj != null && r.equals(obj.r) && p.equals(obj.p);
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
        if (r == null || p == null) {
            throw new InvalidObjectException("All fields must be non-null");
        }
    }
}
