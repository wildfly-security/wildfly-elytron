/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2014 Red Hat, Inc., and individual contributors
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
