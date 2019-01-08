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

import org.wildfly.security.util.StringEnumeration;

/**
 * An abstract base class for permissions which use a bit set to represent actions.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public abstract class AbstractActionSetPermission<This extends AbstractActionSetPermission<This>> extends AbstractActionPermission<This> {
    private static final long serialVersionUID = 897239118282921196L;

    private final StringEnumeration actionEnumeration;
    private final int actionBits;
    private String actions;

    /**
     * Construct a new instance.  The given bits are masked by {@link #actionsMask()} before being stored in the object
     * instance.
     *
     * @param name the permission name
     * @param actionBits the permission action bits
     * @param actionEnumeration the permission actions enumeration
     */
    protected AbstractActionSetPermission(final String name, final int actionBits, final StringEnumeration actionEnumeration) {
        super(name);
        this.actionEnumeration = actionEnumeration;
        this.actionBits = actionBits & actionsMask();
        if (actionBits == actionsMask()) actions = "*";
    }

    /**
     * Construct a new instance.
     *
     * @param name the permission name
     * @param actions the permission actions string
     * @param actionEnumeration the permission actions enumeration
     */
    protected AbstractActionSetPermission(final String name, final String actions, final StringEnumeration actionEnumeration) {
        super(name);
        this.actionEnumeration = actionEnumeration;
        final int actionBits = parseActions(actions);
        this.actionBits = actionBits & actionsMask();
        if (actionBits == actionsMask()) this.actions = "*";
    }

    /**
     * Get the action bits of this permission.
     *
     * @return the action bits
     */
    public final int getActionBits() {
        return actionBits;
    }

    public final boolean actionsEquals(final This permission) {
        return permission != null && actionBits == permission.getActionBits();
    }

    public final boolean impliesActions(final This permission) {
        return permission != null && isSet(actionBits, permission.getActionBits());
    }

    public final boolean impliesActions(final String actions) {
        return impliesActionBits(parseActions(actions));
    }

    /**
     * Determine whether this permission's actions value implies the given action bits.
     *
     * @param actionBits the actions bits to test
     * @return {@code true} if this permission implies the given action bits; {@code false} otherwise
     */
    public final boolean impliesActionBits(final int actionBits) {
        return isSet(this.actionBits, actionBits & actionsMask());
    }

    private int actionsMask() {
        return (1 << actionEnumeration.size()) - 1;
    }

    private int getActionBit(final String actionName) throws IllegalArgumentException {
        return 1 << actionEnumeration.indexOf(actionName);
    }

    private String getActionName(final int bit) throws IllegalArgumentException {
        return actionEnumeration.nameOf(Integer.numberOfTrailingZeros(bit));
    }

    protected final int actionsHashCode() {
        return actionBits;
    }

    /**
     * Get the actions string.  The string is computed the first time this method is called, and cached thereafter.
     *
     * @return the actions string (not {@code null})
     */
    public final String getActions() {
        final String actions = this.actions;
        if (actions != null) {
            return actions;
        }
        return this.actions = PermissionUtil.toActionsString(actionBits, this::getActionName);
    }

    /**
     * Parse the actions string into a bit set.
     *
     * @param actionsString the actions string
     * @return the bit set
     * @throws IllegalArgumentException if the actions string contained an invalid name or invalid syntax
     */
    public final int parseActions(final String actionsString) throws IllegalArgumentException {
        return PermissionUtil.parseActions(actionsString, this::getActionBit);
    }

    public final This withActions(final String actionsString) {
        return withActionBits(parseActions(actionsString));
    }

    public final This withActionsFrom(final This permission) {
        return withActionBits(permission.getActionBits());
    }

    /**
     * Get a permission which is identical to this one, but with new actions which consist of the union of the actions
     * from this permission and the action bits from the given value.  The returned permission may or may not be a new
     * instance, and may be equal to this instance.
     *
     * @param actionBits the action bits
     * @return the permission (not {@code null})
     */
    public final This withActionBits(int actionBits) {
        return withNewActionBits(this.actionBits | actionBits & actionsMask());
    }

    public final This withoutActions(String actionsString) {
        return withoutActionBits(parseActions(actionsString));
    }

    public final This withoutActionsFrom(final This permission) {
        return withoutActionBits(permission.getActionBits());
    }

    /**
     * Get a permission which is identical to this one, but with new actions which consist of the actions
     * from this permission without the action bits from the given value.  The returned permission may or may not be a new
     * instance, and may be equal to this instance.
     *
     * @param actionBits the action bits
     * @return the permission (not {@code null})
     */
    public final This withoutActionBits(int actionBits) {
        return withNewActionBits(this.actionBits & ~actionBits);
    }

    public final This withNewActions(String actionsString) {
        return withNewActionBits(parseActions(actionsString));
    }

    public final This withNewActionsFrom(final This permission) {
        return withNewActionBits(permission.getActionBits());
    }

    /**
     * Get a permission which is identical to this one, but with new action bits as given by {@code actionBits}.
     * The returned permission may or may not be a new instance, and may be equal to this instance.
     *
     * @param actionBits the action bits
     * @return the permission (not {@code null})
     */
    @SuppressWarnings("unchecked")
    public final This withNewActionBits(int actionBits) {
        final int masked = actionBits & actionsMask();
        if (masked == this.actionBits) {
            return (This) this;
        } else {
            return constructWithActionBits(masked);
        }
    }

    /**
     * Construct or return a permission of this type with the same name as this one but with the given action bits.
     *
     * @param actionBits the action bits
     * @return the permission
     */
    protected abstract This constructWithActionBits(int actionBits);

    // private

    private static boolean isSet(final int bits, final int test) {
        return (bits & test) == test;
    }
}
