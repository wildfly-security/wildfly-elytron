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

package org.wildfly.security.permission;

/**
 * A permission which implies nothing, not even itself.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class NoPermission extends AbstractPermission<NoPermission> {
    private static final long serialVersionUID = 2339781690941885693L;

    private static final NoPermission INSTANCE = new NoPermission();

    /**
     * Construct a new instance.
     */
    public NoPermission() {
        super("<no permissions>");
    }

    /**
     * Construct a new instance.  The name parameter is ignored.
     *
     * @param ignored ignored
     */
    public NoPermission(final String ignored) {
        this();
    }

    /**
     * Construct a new instance.  The name and actions parameters are ignored.
     *
     * @param ignored1 ignored
     * @param ignored2 ignored
     */
    public NoPermission(final String ignored1, final String ignored2) {
        this();
    }

    /**
     * Get the no-permission instance.
     *
     * @return the no-permission instance (not {@code null})
     */
    public static NoPermission getInstance() {
        return INSTANCE;
    }

    /**
     * Always returns {@code false}.
     *
     * @param permission ignored
     * @return {@code false}
     */
    public boolean implies(final NoPermission permission) {
        return false;
    }

    /**
     * Always returns {@code true} if the argument is not {@code null}.
     *
     * @param other the permission to compare to
     * @return {@code true} if {@code other} is not {@code null}; {@code false} otherwise
     */
    public boolean equals(final NoPermission other) {
        return other != null;
    }

    /**
     * Get the constant hash code.
     *
     * @return the constant hash code
     */
    public int hashCode() {
        return getClass().hashCode();
    }

    public AbstractPermissionCollection newPermissionCollection() {
        return NoPermissionCollection.getInstance();
    }
}
