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

package org.wildfly.security.manager;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.security.BasicPermission;
import java.security.Permission;
import java.security.PermissionCollection;

import org.wildfly.security.manager._private.SecurityMessages;

/**
 * A permission specific to the WildFly security manager.  The permission name may be one of the following:
 * <ul>
 *     <li>{@code doUnchecked}</li>
 *     <li>{@code getStackInterceptor}</li>
 * </ul>
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class WildFlySecurityManagerPermission extends BasicPermission {

    private static final long serialVersionUID = 1L;

    enum Name {
        doUnchecked,
        getStackInspector,
        ;

        private final WildFlySecurityManagerPermission permission;

        Name() {
            this.permission = new WildFlySecurityManagerPermission(this);
        }

        WildFlySecurityManagerPermission getPermission() {
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

    static final WildFlySecurityManagerPermission DO_UNCHECKED_PERMISSION = Name.doUnchecked.getPermission();
    static final WildFlySecurityManagerPermission GET_STACK_INSPECTOR_PERMISSION = Name.getStackInspector.getPermission();

    static final Name[] values = Name.values();

    private transient Name name;

    WildFlySecurityManagerPermission(final Name name) {
        super(name.toString());
        this.name = name;
    }

    public WildFlySecurityManagerPermission(final String name) {
        this(Name.of(name));
    }

    public WildFlySecurityManagerPermission(final String name, final String actions) {
        this(name);
        if (actions != null && ! actions.isEmpty()) {
            throw SecurityMessages.permission.invalidAction(actions, 0, actions);
        }
    }

    public PermissionCollection newPermissionCollection() {
        return new WildFlySecurityManagerPermissionCollection();
    }

    public boolean implies(final Permission p) {
        return p instanceof WildFlySecurityManagerPermission && name == ((WildFlySecurityManagerPermission) p).name;
    }

    public boolean equals(final Object obj) {
        return obj instanceof WildFlySecurityManagerPermission && name == ((WildFlySecurityManagerPermission) obj).name;
    }

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
