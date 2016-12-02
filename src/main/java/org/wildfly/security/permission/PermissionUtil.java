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

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.UndeclaredThrowableException;
import java.security.AllPermission;
import java.security.Permission;
import java.security.PermissionCollection;
import java.security.Permissions;
import java.util.Arrays;
import java.util.Collection;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.function.BiConsumer;
import java.util.function.BiPredicate;
import java.util.function.Consumer;
import java.util.function.IntFunction;
import java.util.function.LongFunction;
import java.util.function.Predicate;
import java.util.function.ToIntFunction;
import java.util.function.ToLongFunction;

import org.wildfly.common.Assert;
import org.wildfly.security._private.ElytronMessages;

/**
 * General permission utility methods and constants.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class PermissionUtil {

    private PermissionUtil() {
    }

    /**
     * A shared {@link AllPermission} instance.
     */
    public static final Permission ALL_PERMISSION = new AllPermission();

    /**
     * A read-only permission collection which implies {@link AllPermission}.
     */
    public static final PermissionCollection ALL_PERMISSIONS;

    /**
     * A permission collection which is empty.
     */
    public static final PermissionCollection EMPTY_PERMISSION_COLLECTION;

    /**
     * An array with no permissions in it.
     */
    public static final Permission[] NO_PERMISSIONS = new Permission[0];

    static {
        Permissions permissions = new Permissions();
        permissions.add(ALL_PERMISSION);
        permissions.setReadOnly();
        ALL_PERMISSIONS = permissions;
        permissions = new Permissions();
        permissions.setReadOnly();
        EMPTY_PERMISSION_COLLECTION = permissions;
    }

    /**
     * Parse an actions string, using the given function to map action strings to bits.
     *
     * @param actionsString the actions string (must not be {@code null})
     * @param function the mapping function (must not be {@code null})
     * @return the union of all the action bits
     * @throws IllegalArgumentException if {@code function} throws this exception (indicating an invalid action string)
     */
    public static int parseActions(String actionsString, ToIntFunction<String> function) throws IllegalArgumentException {
        Assert.checkNotNullParam("actionsString", actionsString);
        Assert.checkNotNullParam("function", function);
        int actions = 0;
        int pos = 0;
        int idx = actionsString.indexOf(',');
        for (;;) {
            String str;
            if (idx == -1) {
                str = actionsString.substring(pos, actionsString.length()).trim();
                if (! str.isEmpty()) actions |= function.applyAsInt(str);
                return actions;
            } else {
                str = actionsString.substring(pos, idx).trim();
                pos = idx + 1;
                if (! str.isEmpty()) actions |= function.applyAsInt(str);
                idx = actionsString.indexOf(',', pos);
            }
        }
    }

    /**
     * Parse an actions string, using the given function to map action strings to bits.
     *
     * @param actionsString the actions string (must not be {@code null})
     * @param function the mapping function (must not be {@code null})
     * @return the union of all the action bits
     * @throws IllegalArgumentException if {@code function} throws this exception (indicating an invalid action string)
     */
    public static long parseActions(String actionsString, ToLongFunction<String> function) throws IllegalArgumentException {
        Assert.checkNotNullParam("actionsString", actionsString);
        Assert.checkNotNullParam("function", function);
        long actions = 0;
        int pos = 0;
        int idx = actionsString.indexOf(',');
        for (;;) {
            String str;
            if (idx == -1) {
                str = actionsString.substring(pos, actionsString.length()).trim();
                if (! str.isEmpty()) actions |= function.applyAsLong(str);
                return actions;
            } else {
                str = actionsString.substring(pos, idx).trim();
                pos = idx + 1;
                if (! str.isEmpty()) actions |= function.applyAsLong(str);
                idx = actionsString.indexOf(',', pos);
            }
        }
    }

    /**
     * Deparse an action bit set, using the given function to map action bits to strings.  If the bits are all clear,
     * the empty string {@code ""} is returned.
     *
     * @param actionBits the action bit set
     * @param mappingFunction the mapping function (must not be {@code null})
     * @return the actions string (not {@code null})
     */
    public static String toActionsString(int actionBits, IntFunction<String> mappingFunction) {
        Assert.checkNotNullParam("mappingFunction", mappingFunction);
        final StringBuilder sb = new StringBuilder();
        if (actionBits == 0) return "";
        int lb = Integer.highestOneBit(actionBits);
        sb.append(mappingFunction.apply(lb));
        actionBits &= ~lb;
        while (actionBits != 0) {
            lb = Integer.highestOneBit(actionBits);
            sb.append(',').append(mappingFunction.apply(lb));
            actionBits &= ~lb;
        }
        return sb.toString();
    }

    /**
     * Deparse an action bit set, using the given function to map action bits to strings.  If the bits are all clear,
     * the empty string {@code ""} is returned.
     *
     * @param actionBits the action bit set
     * @param mappingFunction the mapping function (must not be {@code null})
     * @return the actions string (not {@code null})
     */
    public static String toActionsString(long actionBits, LongFunction<String> mappingFunction) {
        Assert.checkNotNullParam("mappingFunction", mappingFunction);
        final StringBuilder sb = new StringBuilder();
        if (actionBits == 0) return "";
        long lb = Long.highestOneBit(actionBits);
        sb.append(mappingFunction.apply(lb));
        actionBits &= ~lb;
        while (actionBits != 0) {
            lb = Long.highestOneBit(actionBits);
            sb.append(',').append(mappingFunction.apply(lb));
            actionBits &= ~lb;
        }
        return sb.toString();
    }

    /**
     * Create an iterable view over a permission collection.
     *
     * @param pc the permission collection (must not be {@code null})
     * @return the iterable view (not {@code null})
     */
    public static Iterable<Permission> iterable(PermissionCollection pc) {
        return () -> {
            final Enumeration<Permission> elements = pc.elements();
            return new Iterator<Permission>() {
                public boolean hasNext() {
                    return elements.hasMoreElements();
                }

                public Permission next() {
                    return elements.nextElement();
                }
            };
        };
    }

    /**
     * Perform an action for each permission in the given collection.
     *
     * @param collection the collection (must not be {@code null})
     * @param consumer the consumer to which each permission should be passed (must not be {@code null})
     */
    public static void forEachIn(PermissionCollection collection, Consumer<Permission> consumer) {
        Assert.checkNotNullParam("collection", collection);
        Assert.checkNotNullParam("consumer", consumer);
        final Enumeration<Permission> elements = collection.elements();
        while (elements.hasMoreElements()) {
            consumer.accept(elements.nextElement());
        }
    }

    /**
     * Perform an action for each permission in the given collection.
     *
     * @param collection the collection (must not be {@code null})
     * @param parameter the parameter to pass to the consumer
     * @param consumer the consumer to which each permission should be passed (must not be {@code null})
     * @param <P> the type of the parameter
     * @return the {@code parameter} that was passed in
     */
    public static <P> P forEachIn(PermissionCollection collection, BiConsumer<P, Permission> consumer, P parameter) {
        Assert.checkNotNullParam("collection", collection);
        Assert.checkNotNullParam("consumer", consumer);
        final Enumeration<Permission> elements = collection.elements();
        while (elements.hasMoreElements()) {
            consumer.accept(parameter, elements.nextElement());
        }
        return parameter;
    }

    /**
     * Run a test for each permission in the given collection.  If the predicate returns {@code false} for any element,
     * {@code false} is returned; otherwise, {@code true} is returned.
     *
     * @param collection the collection (must not be {@code null})
     * @param predicate the predicate to apply to each element (must not be {@code null})
     * @return {@code true} if the predicate matched all the permissions in the collection, {@code false} otherwise
     */
    public static boolean forEachIn(PermissionCollection collection, Predicate<Permission> predicate) {
        Assert.checkNotNullParam("collection", collection);
        Assert.checkNotNullParam("predicate", predicate);
        final Enumeration<Permission> elements = collection.elements();
        while (elements.hasMoreElements()) {
            if (! predicate.test(elements.nextElement())) {
                return false;
            }
        }
        return true;
    }

    /**
     * Run a test for each permission in the given collection.  If the predicate returns {@code false} for any element,
     * {@code false} is returned; otherwise, {@code true} is returned.
     *
     * @param collection the collection (must not be {@code null})
     * @param parameter the parameter to pass to the consumer
     * @param predicate the predicate to apply to each element (must not be {@code null})
     * @param <P> the type of the parameter
     * @return {@code true} if the predicate matched all the permissions in the collection, {@code false} otherwise
     */
    public static <P> boolean forEachIn(PermissionCollection collection, BiPredicate<P, Permission> predicate, P parameter) {
        Assert.checkNotNullParam("collection", collection);
        Assert.checkNotNullParam("predicate", predicate);
        final Enumeration<Permission> elements = collection.elements();
        while (elements.hasMoreElements()) {
            if (! predicate.test(parameter, elements.nextElement())) {
                return false;
            }
        }
        return true;
    }

    /**
     * Create a permission collection that is the union of two permission collections.  The permission
     * collections must be read-only.
     *
     * @param pc1 the first permission collection (must not be {@code null})
     * @param pc2 the second permission collection (must not be {@code null})
     * @return a new permission collection that is the union of the two collections (not {@code null})
     */
    public static PermissionCollection union(PermissionCollection pc1, PermissionCollection pc2) {
        Assert.checkNotNullParam("pc1", pc1);
        Assert.checkNotNullParam("pc2", pc2);
        if (! pc1.isReadOnly() || ! pc2.isReadOnly()) {
            throw ElytronMessages.log.permissionCollectionMustBeReadOnly();
        }
        if (pc1.implies(ALL_PERMISSION) || pc2.implies(ALL_PERMISSION)) {
            return ALL_PERMISSIONS;
        } else {
            return new UnionPermissionCollection(pc1, pc2);
        }
    }

    /**
     * Create a permission collection that is the intersection of two permission collections.  The permission
     * collections must be read-only.
     *
     * @param pc1 the first permission collection (must not be {@code null})
     * @param pc2 the second permission collection (must not be {@code null})
     * @return a new permission collection that is the intersection of the two collections (not {@code null})
     */
    public static PermissionCollection intersection(PermissionCollection pc1, PermissionCollection pc2) {
        Assert.checkNotNullParam("pc1", pc1);
        Assert.checkNotNullParam("pc2", pc2);
        if (! pc1.isReadOnly() || ! pc2.isReadOnly()) {
            throw ElytronMessages.log.permissionCollectionMustBeReadOnly();
        }
        if (pc1.implies(ALL_PERMISSION)) {
            return pc2;
        } else if (pc2.implies(ALL_PERMISSION)) {
            return pc1;
        } else {
            return new IntersectionPermissionCollection(pc1, pc2);
        }
    }

    /**
     * Determine if one collection implies all the permissions in the other collection.
     *
     * @param collection the collection to check against (must not be {@code null})
     * @param testCollection the collection whose permissions are to be tested (must not be {@code null})
     * @return {@code true} if {@code collection} implies all of the permissions in {@code testCollection}, {@code false} otherwise
     */
    public static boolean impliesAll(PermissionCollection collection, PermissionCollection testCollection) {
        return forEachIn(collection, PermissionCollection::implies, testCollection);
    }

    /**
     * Determine if two permission collections are equal, that is, each collection implies all of the permissions in the
     * other collection.
     *
     * @param pc1 the first collection (must not be {@code null})
     * @param pc2 the second collection (must not be {@code null})
     * @return {@code true} if the collections imply one another, {@code false} otherwise
     */
    public static boolean equals(PermissionCollection pc1, PermissionCollection pc2) {
        return impliesAll(pc1, pc2) && impliesAll(pc2, pc1);
    }

    /**
     * Add all of the permissions from the source collection to the target collection.
     *
     * @param target the target collection (must not be {@code null})
     * @param source the source collection (must not be {@code null})
     * @return the target collection (not {@code null})
     */
    public static PermissionCollection addAll(PermissionCollection target, PermissionCollection source) {
        return forEachIn(source, PermissionCollection::add, target);
    }

    /**
     * Add all of the permissions from the source collection to the target collection.
     *
     * @param target the target collection (must not be {@code null})
     * @param source the source collection (must not be {@code null})
     * @return the target collection (not {@code null})
     */
    public static PermissionCollection addAll(PermissionCollection target, Collection<Permission> source) {
        source.forEach(target::add);
        return target;
    }

    /**
     * Add a permission to a collection, returning the target collection.  If the permission is {@code null}, it is
     * not added.
     *
     * @param target the target collection (must not be {@code null})
     * @param source the permission to add
     * @return the target collection (not {@code null})
     */
    public static PermissionCollection add(PermissionCollection target, Permission source) {
        Assert.checkNotNullParam("target", target);
        if (source != null) target.add(source);
        return target;
    }

    /**
     * Instantiate a permission with the given class name, permission name, and actions.
     *
     * @param classLoader the class loader to search in ({@code null} indicates the system class loader)
     * @param className the name of the permission class to instantiate (must not be {@code null})
     * @param name the permission name (may be {@code null} if allowed by the permission class)
     * @param actions the permission actions (may be {@code null} if allowed by the permission class)
     * @return the permission object (not {@code null})
     * @throws InvalidPermissionClassException if the permission class does not exist or is not valid
     * @throws ClassCastException if the class name does not refer to a subclass of {@link Permission}
     */
    public static Permission createPermission(final ClassLoader classLoader, final String className, final String name, final String actions) {
        Assert.checkNotNullParam("className", className);
        final Class<? extends Permission> permissionClass;
        try {
            permissionClass = Class.forName(className, true, classLoader).asSubclass(Permission.class);
        } catch (ClassNotFoundException e) {
            throw ElytronMessages.log.permissionClassMissing(className, e);
        }
        return createPermission(permissionClass, name, actions);
    }

    /**
     * Instantiate a permission with the given class, permission name, and actions.
     *
     * @param permissionClass the permission class to instantiate (must not be {@code null})
     * @param name the permission name (may be {@code null} if allowed by the permission class)
     * @param actions the permission actions (may be {@code null} if allowed by the permission class)
     * @return the permission object (not {@code null})
     * @throws InvalidPermissionClassException if the permission class does not exist or is not valid
     */
    public static Permission createPermission(final Class<? extends Permission> permissionClass, final String name, final String actions) {
        Assert.checkNotNullParam("permissionClass", permissionClass);
        Constructor<? extends Permission> noArgs = null;
        Constructor<? extends Permission> oneArg = null;
        Constructor<? extends Permission> twoArg = null;
        for (Constructor<?> raw : permissionClass.getConstructors()) {
            @SuppressWarnings("unchecked")
            Constructor<? extends Permission> ctor = (Constructor<? extends Permission>) raw;
            final Class<?>[] parameterTypes = ctor.getParameterTypes();
            if (parameterTypes.length == 2 && parameterTypes[0] == String.class && parameterTypes[1] == String.class) {
                twoArg = ctor;
            } else if (parameterTypes.length == 1 && parameterTypes[0] == String.class) {
                oneArg = ctor;
            } else if (parameterTypes.length == 0) {
                noArgs = ctor;
            }
        }
        try {
            if (twoArg != null && name != null && actions != null) {
                return twoArg.newInstance(name, actions);
            } else if (oneArg != null && name != null) {
                return oneArg.newInstance(name);
            } else if (noArgs != null) {
                return noArgs.newInstance();
            } else {
                // no constructor for given params found
                if ((oneArg != null || twoArg != null) && name == null) {
                    throw new InvalidNamedArgumentException("name");
                } else if (twoArg != null && actions == null) {
                    throw new InvalidNamedArgumentException("actions");
                }
                throw ElytronMessages.log.noPermissionConstructor(permissionClass.getName());
            }
        } catch (IllegalAccessException e) {
            throw new IllegalAccessError(e.getMessage());
        } catch (InstantiationException e) {
            throw ElytronMessages.log.permissionInstantiation(permissionClass.getName(), e);
        } catch (InvocationTargetException e) {
            try {
                throw e.getCause();
            } catch (Error | RuntimeException cause) {
                throw cause;
            } catch (Throwable cause) {
                throw new UndeclaredThrowableException(cause);
            }
        }
    }

    /**
     * Get a read-only collection of the given permissions.
     *
     * @param permissions the permissions to assign
     * @return the read-only collection
     */
    public static PermissionCollection readOnlyCollectionOf(Permission... permissions) {
        final int length = permissions.length;
        if (length == 0) {
            return EMPTY_PERMISSION_COLLECTION;
        } else {
            Permissions collection = new Permissions();
            addAll(collection, Arrays.asList(permissions));
            collection.setReadOnly();
            return collection;
        }
    }
}
