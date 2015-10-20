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

package org.wildfly.security.auth.permission;

import java.security.Permission;

/**
 * Establish whether the current identity has permission to complete an authentication ("log in").
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class LoginPermission extends Permission {

    private static final long serialVersionUID = - 5776174571770792690L;

    /**
     * Construct a new instance.
     */
    public LoginPermission() {
        super("");
    }

    /**
     * Construct a new instance.
     *
     * @param name ignored
     */
    public LoginPermission(@SuppressWarnings("unused") final String name) {
        super("");
    }

    /**
     * Construct a new instance.
     *
     * @param name ignored
     * @param actions ignored
     */
    public LoginPermission(@SuppressWarnings("unused") final String name, @SuppressWarnings("unused") final String actions) {
        super("");
    }

    /**
     * Determine whether this permission implies another permission.
     *
     * @param permission the other permission
     * @return {@code true} if this permission implies the other permission, {@code false} otherwise
     */
    public boolean implies(final Permission permission) {
        return permission instanceof LoginPermission;
    }

    /**
     * Determine whether this permission implies another permission.
     *
     * @param permission the other permission
     * @return {@code true} if this permission implies the other permission, {@code false} otherwise
     */
    public boolean implies(final LoginPermission permission) {
        return permission != null;
    }

    /**
     * Determine whether this permission equals another permission.
     *
     * @param obj the other permission
     * @return {@code true} if this permission equals the other permission, {@code false} otherwise
     */
    public boolean equals(final Object obj) {
        return obj instanceof LoginPermission;
    }

    /**
     * Determine whether this permission equals another permission.
     *
     * @param obj the other permission
     * @return {@code true} if this permission equals the other permission, {@code false} otherwise
     */
    public boolean equals(final Permission obj) {
        return obj instanceof LoginPermission;
    }

    /**
     * Determine whether this permission equals another permission.
     *
     * @param obj the other permission
     * @return {@code true} if this permission equals the other permission, {@code false} otherwise
     */
    public boolean equals(final LoginPermission obj) {
        return obj != null;
    }

    /**
     * Get the hash code for this permission.
     *
     * @return the hash code for this permission
     */
    public int hashCode() {
        return 239;
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
