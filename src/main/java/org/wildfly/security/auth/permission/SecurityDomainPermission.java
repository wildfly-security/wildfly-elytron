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

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.ObjectStreamField;
import java.security.Permission;

import org.wildfly.security.permission.PermissionActions;

/**
 * A permission controlling access to security domains.
 */
public final class SecurityDomainPermission extends Permission {

    private static final long serialVersionUID = 8533735187740371169L;

    /**
     * @serialField actions String The permission actions.
     */
    private static final ObjectStreamField[] serialPersistentFields = new ObjectStreamField[] {
        new ObjectStreamField("actions", String.class),
    };

    private transient String actionString;
    private transient int actions;

    /**
     * Construct a new instance with no actions.
     *
     * @param name the security domain name
     */
    public SecurityDomainPermission(final String name) {
        super(name);
        actions = 0;
    }

    /**
     * Construct a new instance.
     *
     * @param name the security domain name
     * @param actions the actions string
     */
    public SecurityDomainPermission(final String name, final String actions) {
        super(name);
        this.actions = PermissionActions.parseActionStringToInt(Action.class, actions);
    }

    /**
     * Determine whether this permission implies another permission.
     *
     * @param permission the other permission
     * @return {@code true} if this permission implies the other permission, {@code false} otherwise
     */
    public boolean implies(final Permission permission) {
        return permission instanceof SecurityDomainPermission && implies((SecurityDomainPermission) permission);
    }

    /**
     * Determine whether this permission implies another permission.
     *
     * @param permission the other permission
     * @return {@code true} if this permission implies the other permission, {@code false} otherwise
     */
    public boolean implies(final SecurityDomainPermission permission) {
        return (actions & permission.actions) == permission.actions && getName().equals(permission.getName());
    }

    /**
     * Determine whether this permission equals another permission.
     *
     * @param obj the other permission
     * @return {@code true} if this permission equals the other permission, {@code false} otherwise
     */
    public boolean equals(final Object obj) {
        return obj instanceof SecurityDomainPermission && equals((SecurityDomainPermission) obj);
    }

    /**
     * Determine whether this permission equals another permission.
     *
     * @param permission the other permission
     * @return {@code true} if this permission equals the other permission, {@code false} otherwise
     */
    public boolean equals(final SecurityDomainPermission permission) {
        return actions == permission.actions && getName().equals(permission.getName());
    }

    /**
     * Get the hash code for this permission.
     *
     * @return the hash code for this permission
     */
    public int hashCode() {
        return getName().hashCode() * 4 + actions;
    }

    /**
     * Get the actions for this permission.
     *
     * @return the actions for this permission
     */
    public String getActions() {
        String actionString = this.actionString;
        if (actionString == null) {
            actionString = this.actionString = PermissionActions.getCanonicalActionString(Action.class, actions);
        }
        return actionString;
    }

    /**
     * The permission actions.  This enum is guaranteed to never be re-ordered.
     */
    enum Action {
        // Do not re-order, ever
        /**
         * The "create" security domain permission action.
         */
        create,
        /**
         * The "access" security domain permission action.
         */
        access,
        ;
    }

    private void readObject(ObjectInputStream ois) throws IOException, ClassNotFoundException {
        final ObjectInputStream.GetField getField = ois.readFields();
        this.actions = PermissionActions.parseActionStringToInt(Action.class, (String) getField.get("actions", ""));
    }

    private void writeObject(ObjectOutputStream oos) throws IOException {
        final ObjectOutputStream.PutField putField = oos.putFields();
        putField.put("actions", getActions());
        oos.writeFields();
    }
}
