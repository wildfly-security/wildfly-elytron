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

import java.security.Permission;

import org.wildfly.common.Assert;

/**
 * An abstract base class for named permissions that have actions, with useful API and implementation methods.  All
 * the constraints described in {@link AbstractNamedPermission} apply.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public abstract class AbstractActionPermission<This extends AbstractActionPermission<This>> extends AbstractNamedPermission<This> {
    private static final long serialVersionUID = - 1366777243917643233L;

    /**
     * Construct a new instance.
     *
     * @param name the permission name
     */
    protected AbstractActionPermission(final String name) {
        super(name);
    }

    /**
     * Determine whether this permission implies another permission.  Returns {@code true} if
     * both {@link #impliesActions(AbstractActionPermission)} and {@link #impliesName(AbstractNamedPermission)}
     * return {@code true}.
     *
     * @param permission the other permission
     * @return {@code true} if this permission implies the other; {@code false} otherwise
     */
    public final boolean implies(final This permission) {
        return permission != null && impliesActions(permission) && impliesName(permission);
    }

    /**
     * Determine whether this permission is equal to another permission.  Returns {@code true} if
     * both {@link #actionsEquals(AbstractActionPermission)} and {@link #nameEquals(AbstractNamedPermission)}
     * return {@code true}.
     *
     * @param permission the other permission
     * @return {@code true} if this permission implies the other; {@code false} otherwise
     */
    public final boolean equals(final This permission) {
        return super.equals(permission) && actionsEquals(permission);
    }

    public final int hashCode() {
        return super.hashCode() * 53 + actionsHashCode();
    }

    /**
     * Determine whether the actions of this permission are equal to the given {@code actions}.
     *
     * @param actions the actions string (must not be {@code null})
     * @return {@code true} if the actions are equal, {@code false} otherwise
     */
    public abstract boolean actionsEquals(String actions);

    /**
     * Determine whether the actions of this permission are equal to the actions of given {@code permission}.  If
     * the permission is not of the same type as this permission, {@code false} is returned.
     *
     * @param permission the permission whose actions are to be compared
     * @return {@code true} if the actions are equal, {@code false} otherwise
     */
    @SuppressWarnings("unchecked")
    public final boolean actionsEquals(Permission permission) {
        return permission != null && permission.getClass() == getClass() && actionsEquals((This) permission);
    }

    /**
     * Determine whether the actions of this permission are equal to the actions of given {@code permission}.
     *
     * @param permission the permission whose actions are to be compared
     * @return {@code true} if the actions are equal, {@code false} otherwise
     */
    public abstract boolean actionsEquals(This permission);

    /**
     * Get the actions hash code.
     *
     * @return the actions hash code
     */
    protected abstract int actionsHashCode();

    /**
     * Determine whether this permission's actions value implies the given actions value.
     *
     * @param actions the actions to test (must not be {@code null})
     * @return {@code true} if this permission implies the other; {@code false} otherwise
     */
    public abstract boolean impliesActions(String actions);

    /**
     * Determine whether this permission's actions value implies the actions of the given {@code permission}.  If
     * the permission is not of the same type as this permission, {@code false} is returned.
     *
     * @param permission the permission whose actions are to be compared
     * @return {@code true} if this permission implies the other; {@code false} otherwise
     */
    @SuppressWarnings("unchecked")
    public final boolean impliesActions(Permission permission) {
        return permission != null && permission.getClass() == getClass() && impliesActions((This) permission);
    }

    /**
     * Determine whether this permission's actions value implies the actions of the given {@code permission}.
     *
     * @param permission the permission whose actions are to be compared
     * @return {@code true} if this permission implies the other; {@code false} otherwise
     */
    public abstract boolean impliesActions(This permission);

    /**
     * Get a permission which is identical to this one, but with new actions which consist of the union of the actions
     * from this permission and the actions from the given string.  The returned permission may or may not be a new
     * instance, and may be equal to this instance.
     *
     * @param actionsString the actions string (must not be {@code null})
     * @return the permission (not {@code null})
     */
    public abstract This withActions(String actionsString);

    /**
     * Get a permission which is identical to this one, but with new actions which consist of the union of the actions
     * from this permission and the actions from the given permission.  The returned permission may or may not be a new
     * instance, and may be equal to this instance.
     *
     * @param permission the other permission (must not be {@code null})
     * @return the permission (not {@code null})
     */
    public This withActionsFrom(This permission) {
        Assert.checkNotNullParam("permission", permission);
        return withActions(permission.getActions());
    }

    /**
     * Get a permission which is identical to this one, but with new actions which consist of the actions
     * from this permission without the actions from the given string.  The returned permission may or may not be a new
     * instance, and may be equal to this instance.
     *
     * @param actionsString the actions string (must not be {@code null})
     * @return the permission (not {@code null})
     */
    public abstract This withoutActions(String actionsString);

    /**
     * Get a permission which is identical to this one, but with new actions which consist of the actions
     * from this permission without the actions from the given permission.  The returned permission may or may not be a new
     * instance, and may be equal to this instance.
     *
     * @param permission the other permission (must not be {@code null})
     * @return the permission (not {@code null})
     */
    public This withoutActionsFrom(This permission) {
        Assert.checkNotNullParam("permission", permission);
        return withActions(permission.getActions());
    }

    /**
     * Get a permission which is identical to this one, but with new actions as given by {@code actionsString}.
     * The returned permission may or may not be a new instance, and may be equal to this instance.
     *
     * @param actionsString the actions string (must not be {@code null})
     * @return the permission (not {@code null})
     */
    public abstract This withNewActions(String actionsString);

    /**
     * Get a permission which is identical to this one, but with new actions as given by {@code actionsString}.
     * The returned permission may or may not be a new instance, and may be equal to this instance.
     *
     * @param permission the other permission (must not be {@code null})
     * @return the permission (not {@code null})
     */
    public This withNewActionsFrom(This permission) {
        Assert.checkNotNullParam("permission", permission);
        return withNewActions(permission.getActions());
    }
}
