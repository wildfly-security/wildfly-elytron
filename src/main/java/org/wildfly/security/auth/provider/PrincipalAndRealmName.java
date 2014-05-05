/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2014, Red Hat, Inc., and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */

package org.wildfly.security.auth.provider;

import java.io.Serializable;
import java.security.Principal;

/**
 * A name-and-realm pair.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class PrincipalAndRealmName implements Serializable, Comparable<PrincipalAndRealmName> {

    private static final long serialVersionUID = -2842106980530578966L;

    private final Principal principal;
    private final String realmName;

    /**
     * Construct a new instance.
     *
     * @param principal the principal (must not be {@code null})
     * @param realmName the realm name (must not be {@code null})
     */
    public PrincipalAndRealmName(final Principal principal, final String realmName) {
        if (principal == null) {
            throw new IllegalArgumentException("principal is null");
        }
        if (realmName == null) {
            throw new IllegalArgumentException("realmName is null");
        }
        this.principal = principal;
        this.realmName = realmName;
    }

    /**
     * Get the name.
     *
     * @return the name (not {@code null})
     */
    public Principal getPrincipal() {
        return principal;
    }

    /**
     * Get the realm name.
     *
     * @return the realm name (not {@code null})
     */
    public String getRealmName() {
        return realmName;
    }

    /**
     * Determine if this object is equal to another.
     *
     * @param other the other
     * @return {@code true} if they are equal, {@code false} otherwise
     */
    public boolean equals(final Object other) {
        return other instanceof PrincipalAndRealmName && equals((PrincipalAndRealmName) other);
    }

    /**
     * Determine if this object is equal to another.
     *
     * @param other the other
     * @return {@code true} if they are equal, {@code false} otherwise
     */
    public boolean equals(final PrincipalAndRealmName other) {
        return other != null && principal.equals(other.principal) && realmName.equals(other.realmName);
    }

    /**
     * Determine the hash code of this object.
     *
     * @return the hash code
     */
    public int hashCode() {
        return realmName.hashCode() * 17 + principal.hashCode();
    }

    /**
     * Compare this {@code NameAndRealm} to another.
     *
     * @param other the other object
     * @return 0 if they are equal, -1 if the other object comes before this one, or 1 if the other object comes after this one
     */
    public int compareTo(final PrincipalAndRealmName other) {
        int res = realmName.compareTo(other.realmName);
        if (res == 0) res = principal.getClass().getName().compareTo(other.principal.getClass().getName());
        if (res == 0) res = principal.getName().compareTo(other.principal.getName());
        return res;
    }
}
