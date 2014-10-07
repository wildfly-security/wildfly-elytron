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
