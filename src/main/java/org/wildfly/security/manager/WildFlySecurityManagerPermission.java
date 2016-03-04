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

import org.wildfly.security.permission.AbstractNameSetOnlyPermission;
import org.wildfly.security.util.StringEnumeration;
import org.wildfly.security.util.StringMapping;

/**
 * A permission specific to the WildFly security manager.  The permission name may be one of the following:
 * <ul>
 *     <li>{@code doUnchecked}</li>
 *     <li>{@code getStackInterceptor}</li>
 * </ul>
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class WildFlySecurityManagerPermission extends AbstractNameSetOnlyPermission<WildFlySecurityManagerPermission> {

    private static final long serialVersionUID = 1L;

    private static final StringEnumeration strings = StringEnumeration.of(
        "doUnchecked",
        "getStackInspector"
    );

    static final StringMapping<WildFlySecurityManagerPermission> mapping = new StringMapping<>(strings, WildFlySecurityManagerPermission::new);

    private static final WildFlySecurityManagerPermission allPermission = new WildFlySecurityManagerPermission("*");

    // these are used in various other classes in this package
    static final WildFlySecurityManagerPermission doUncheckedPermission = mapping.getItemById(0);
    static final WildFlySecurityManagerPermission getStackInspectorPermission = mapping.getItemById(1);

    /**
     * Construct a new instance.
     *
     * @param name the permission name (must not be {@code null})
     */
    public WildFlySecurityManagerPermission(final String name) {
        this(name, null);
    }

    /**
     * Construct a new instance.
     *
     * @param name the permission name (must not be {@code null})
     * @param actions the actions string (must be empty or {@code null})
     */
    public WildFlySecurityManagerPermission(final String name, final String actions) {
        super(name, strings);
        requireEmptyActions(actions);
    }

    public WildFlySecurityManagerPermission withName(final String name) {
        return name.equals("*") ? allPermission : mapping.getItemByString(name);
    }
}
