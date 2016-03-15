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
