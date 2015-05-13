/*
 * JBoss, Home of Professional Open Source
 * Copyright 2013 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.auth.permission;

import java.security.Permission;

/**
 * The permission to run as another principal within some security domain.
 */
public final class RunAsPrincipalPermission extends Permission {

    private static final long serialVersionUID = -3361334389433669815L;

    /**
     * Construct a new instance.
     *
     * @param name the principal name
     * @param securityDomainName the security domain name
     */
    public RunAsPrincipalPermission(final String name, final String securityDomainName) {
        super(compileName(name, securityDomainName));
    }

    private static String compileName(final String name, final String securityDomainName) {
        if (securityDomainName.indexOf(':') != -1) {
            throw new IllegalArgumentException("Security domain name is invalid");
        }
        return securityDomainName + ":" + name;
    }

    /**
     * Determine whether this permission implies another permission.
     *
     * @param permission the other permission
     * @return {@code true} if this permission implies the other permission, {@code false} otherwise
     */
    public boolean implies(final Permission permission) {
        return equals(permission);
    }

    /**
     * Determine whether this permission equals another permission.
     *
     * @param obj the other permission
     * @return {@code true} if this permission equals the other permission, {@code false} otherwise
     */
    public boolean equals(final Object obj) {
        return obj instanceof RunAsPrincipalPermission && equals((RunAsPrincipalPermission) obj);
    }

    /**
     * Determine whether this permission equals another permission.
     *
     * @param perm the other permission
     * @return {@code true} if this permission equals the other permission, {@code false} otherwise
     */
    public boolean equals(final RunAsPrincipalPermission perm) {
        return perm != null && perm.getName().equals(getName());
    }

    /**
     * Get the hash code for this permission.
     *
     * @return the hash code for this permission
     */
    public int hashCode() {
        return getName().hashCode();
    }

    /**
     * Get the actions for this permission (always an empty string).
     *
     * @return an empty string
     */
    public String getActions() {
        return "";
    }
}
