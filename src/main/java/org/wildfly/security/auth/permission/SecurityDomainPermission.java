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

public final class SecurityDomainPermission extends Permission {

    private static final long serialVersionUID = 8533735187740371169L;

    private static final ObjectStreamField[] serialPersistentFields = new ObjectStreamField[] {
        new ObjectStreamField("actions", String.class),
    };

    private transient String actionString;
    private transient int actions;

    public SecurityDomainPermission(final String name) {
        super(name);
        actions = 0;
    }

    public SecurityDomainPermission(final String name, final String actions) {
        super(name);
        this.actions = PermissionActions.parseActionStringToInt(Action.class, actions);
    }

    public boolean implies(final Permission permission) {
        return permission instanceof SecurityDomainPermission && implies((SecurityDomainPermission) permission);
    }

    public boolean implies(final SecurityDomainPermission permission) {
        return (actions & permission.actions) == permission.actions && getName().equals(permission.getName());
    }

    public boolean equals(final Object obj) {
        return obj instanceof SecurityDomainPermission && equals((SecurityDomainPermission) obj);
    }

    public boolean equals(final SecurityDomainPermission permission) {
        return actions == permission.actions && getName().equals(permission.getName());
    }

    public int hashCode() {
        return getName().hashCode() * 4 + actions;
    }

    public String getActions() {
        String actionString = this.actionString;
        if (actionString == null) {
            actionString = this.actionString = PermissionActions.getCanonicalActionString(Action.class, actions);
        }
        return actionString;
    }

    enum Action {
        // Do not re-order, ever
        create,
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
