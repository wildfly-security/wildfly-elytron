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

package org.wildfly.security.permission;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.security.Permission;
import java.security.PermissionCollection;

import org.wildfly.security.manager._private.SecurityMessages;

/**
 * A general Elytron permission.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class ElytronPermission extends Permission {

    private static final long serialVersionUID = 6124294238228442419L;

    enum Name {
        createAuthenticator,
        createAuthenticationContextConfigurationClient,
        ;

        private final ElytronPermission permission;

        Name() {
            this.permission = new ElytronPermission(this);
        }

        ElytronPermission getPermission() {
            return permission;
        }

        public static Name of(final String name) {
            try {
                return valueOf(name);
            } catch (IllegalArgumentException ignored) {
                throw SecurityMessages.permission.invalidName(name);
            }
        }

    }

    static final Name[] values = Name.values();

    private transient Name name;

    ElytronPermission(final Name name) {
        super(name.toString());
        this.name = name;
    }

    /**
     * Construct a new instance.
     *
     * @param name the name of the permission
     */
    public ElytronPermission(final String name) {
        this(Name.of(name));
    }

    /**
     * Construct a new instance.
     *
     * @param name the name of the permission
     * @param actions the actions (should be empty)
     */
    public ElytronPermission(final String name, final String actions) {
        this(name);
        if (actions != null && ! actions.isEmpty()) {
            throw SecurityMessages.permission.invalidAction(actions, 0, actions);
        }
    }

    /**
     * Get the specialized permission collection type for this permission class.
     *
     * @return a new permission collection
     */
    public PermissionCollection newPermissionCollection() {
        return new ElytronPermissionCollection();
    }

    /**
     * Get the actions.
     *
     * @return the actions (always empty)
     */
    public String getActions() {
        return "";
    }

    /**
     * Determine if this permission implies the other permission.  True if the permission is an {@code ElytronPermission}
     * and the name of the permission is equal to the name of this permission.
     *
     * @param p the permission to test
     * @return {@code true} if the given permission is implied by this one, {@code false} otherwise
     */
    public boolean implies(final Permission p) {
        return p instanceof ElytronPermission && name == ((ElytronPermission) p).name;
    }

    /**
     * Determine if this permission equals the other object.  True if the object is an {@code ElytronPermission}
     * and the name of the permission is equal to the name of this permission.
     *
     * @param obj the object to test
     * @return {@code true} if the given object is equal to this one, {@code false} otherwise
     */
    public boolean equals(final Object obj) {
        return obj instanceof ElytronPermission && name == ((ElytronPermission) obj).name;
    }

    /**
     * Get the hash code of this permission.
     *
     * @return the hash code of this permission
     */
    public int hashCode() {
        return (name.ordinal() + 5) * 51;
    }

    Name getKind() {
        return name;
    }

    private void readObject(ObjectInputStream ois) throws IOException, ClassNotFoundException {
        ois.defaultReadObject();
        name = Name.of(getName());
    }

}
