/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2013, Red Hat, Inc., and individual contributors
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

import java.io.FileDescriptor;
import java.lang.reflect.Field;
import java.lang.reflect.Member;
import java.net.InetAddress;
import java.security.AccessControlContext;
import java.security.AccessController;
import java.security.CodeSource;
import java.security.Permission;
import java.security.Principal;
import java.security.PrivilegedAction;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.security.ProtectionDomain;
import java.util.Arrays;
import java.util.Map;
import java.util.Properties;
import java.util.PropertyPermission;
import java.util.concurrent.atomic.AtomicIntegerFieldUpdater;
import java.util.concurrent.atomic.AtomicLongFieldUpdater;
import java.util.concurrent.atomic.AtomicReferenceFieldUpdater;

import org.kohsuke.MetaInfServices;
import org.wildfly.security.ParametricPrivilegedAction;
import org.wildfly.security.ParametricPrivilegedExceptionAction;
import org.wildfly.security.manager.action.ClearPropertyAction;
import org.wildfly.security.manager.action.GetClassLoaderAction;
import org.wildfly.security.manager.action.GetContextClassLoaderAction;
import org.wildfly.security.manager.action.GetEnvironmentAction;
import org.wildfly.security.manager.action.GetProtectionDomainAction;
import org.wildfly.security.manager.action.GetSystemPropertiesAction;
import org.wildfly.security.manager.action.ReadEnvironmentPropertyAction;
import org.wildfly.security.manager.action.ReadPropertyAction;
import org.wildfly.security.manager.action.SetContextClassLoaderAction;
import org.wildfly.security.manager.action.WritePropertyAction;
import sun.reflect.Reflection;

import static java.lang.System.clearProperty;
import static java.lang.System.getProperties;
import static java.lang.System.getProperty;
import static java.lang.System.getSecurityManager;
import static java.lang.System.getenv;
import static java.lang.System.setProperty;
import static java.lang.Thread.currentThread;
import static java.security.AccessController.doPrivileged;
import static org.wildfly.security.manager.WildFlySecurityManagerPermission.DO_UNCHECKED_PERMISSION;
import static org.wildfly.security.manager._private.SecurityMessages.access;

/**
 * The security manager.  This security manager implementation can be switched on and off on a per-thread basis,
 * and additionally logs access violations in a way that should be substantially clearer than most JDK implementations.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
@MetaInfServices
public final class WildFlySecurityManager extends SecurityManager {

    private static final Permission SECURITY_MANAGER_PERMISSION = new RuntimePermission("setSecurityManager");
    private static final Permission PROPERTIES_PERMISSION = new PropertyPermission("*", "read,write");
    private static final Permission ENVIRONMENT_PERMISSION = new RuntimePermission("getenv.*");
    private static final Permission GET_CLASS_LOADER_PERMISSION = new RuntimePermission("getClassLoader");
    private static final Permission SET_CLASS_LOADER_PERMISSION = new RuntimePermission("setClassLoader");

    static class Context {
        boolean checking = true;
        boolean entered = false;
        ParametricPrivilegedAction<Object, Object> action1;
        ParametricPrivilegedExceptionAction<Object, Object> action2;
        Object parameter;
    }

    private static final ThreadLocal<Context> CTX = new ThreadLocal<Context>() {
        protected Context initialValue() {
            return new Context();
        }
    };

    private static final Field PD_STACK;
    private static final WildFlySecurityManager INSTANCE;
    private static final boolean hasGetCallerClass;
    private static final int callerOffset;

    static {
        PD_STACK = doPrivileged(new GetAccessibleDeclaredFieldAction(AccessControlContext.class, "context"));
        INSTANCE = doPrivileged(new PrivilegedAction<WildFlySecurityManager>() {
            public WildFlySecurityManager run() {
                return new WildFlySecurityManager();
            }
        });
        boolean result = false;
        int offset = 0;
        try {
            //noinspection deprecation
            result = Reflection.getCallerClass(1) == WildFlySecurityManager.class || Reflection.getCallerClass(2) == WildFlySecurityManager.class;
            //noinspection deprecation
            offset = Reflection.getCallerClass(1) == Reflection.class ? 2 : 1;

        } catch (Throwable ignored) {}
        hasGetCallerClass = result;
        callerOffset = offset;
    }

    private static final RuntimePermission ACCESS_DECLARED_MEMBERS_PERMISSION = new RuntimePermission("accessDeclaredMembers");

    /**
     * Construct a new instance.  If the caller does not have permission to do so, this method will throw an exception.
     *
     * @throws SecurityException if the caller does not have permission to create a security manager instance
     */
    public WildFlySecurityManager() throws SecurityException {
    }

    @Deprecated
    public static void install() throws SecurityException {
        if (System.getSecurityManager() instanceof WildFlySecurityManager) return;
        System.setSecurityManager(new WildFlySecurityManager());
    }

    @SuppressWarnings("deprecation")
    static Class<?> getCallerClass(int n) {
        if (hasGetCallerClass) {
            return Reflection.getCallerClass(n + callerOffset);
        } else {
            return getCallStack()[n + callerOffset];
        }
    }

    static Class<?>[] getCallStack() {
        return INSTANCE.getClassContext();
    }

    /**
     * Determine whether the security manager is currently checking permissions.
     *
     * @return {@code true} if the security manager is currently checking permissions
     */
    public static boolean isChecking() {
        final SecurityManager sm = getSecurityManager();
        return sm instanceof WildFlySecurityManager ? doCheck() : sm != null;
    }

    /**
     * Perform a permission check.
     *
     * @param perm the permission to check
     * @throws SecurityException if the check fails
     */
    public void checkPermission(final Permission perm) throws SecurityException {
        checkPermission(perm, AccessController.getContext());
    }

    /**
     * Perform a permission check.
     *
     * @param perm the permission to check
     * @param context the security context to use for the check (must be an {@link AccessControlContext} instance)
     * @throws SecurityException if the check fails
     */
    public void checkPermission(final Permission perm, final Object context) throws SecurityException {
        if (context instanceof AccessControlContext) {
            checkPermission(perm, (AccessControlContext) context);
        } else {
            throw access.unknownContext();
        }
    }

    /**
     * Find the protection domain in the given list which denies a permission, or {@code null} if the permission
     * check would pass.
     *
     * @param permission the permission to test
     * @param domains the protection domains to try
     * @return the first denying protection domain, or {@code null} if there is none
     */
    public static ProtectionDomain findAccessDenial(final Permission permission, final ProtectionDomain... domains) {
        if (domains != null) for (ProtectionDomain domain : domains) {
            if (! domain.implies(permission)) {
                return domain;
            }
        }
        return null;
    }

    /**
     * Try a permission check.  Any violations will be logged to the {@code org.wildfly.security.access} category
     * at a {@code DEBUG} level.
     *
     * @param permission the permission to check
     * @param domains the protection domains to try
     * @return {@code true} if the access check succeeded, {@code false} otherwise
     */
    public static boolean tryCheckPermission(final Permission permission, final ProtectionDomain... domains) {
        final ProtectionDomain protectionDomain = findAccessDenial(permission, domains);
        if (protectionDomain != null) {
            final Context ctx = CTX.get();
            if (! ctx.entered) {
                ctx.entered = true;
                try {
                    final CodeSource codeSource = protectionDomain.getCodeSource();
                    final ClassLoader classLoader = protectionDomain.getClassLoader();
                    final Principal[] principals = protectionDomain.getPrincipals();
                    if (principals == null || principals.length == 0) {
                        access.accessCheckFailed(permission, codeSource, classLoader);
                    } else {
                        access.accessCheckFailed(permission, codeSource, classLoader, Arrays.toString(principals));
                    }
                } finally {
                    ctx.entered = true;
                }
            }
            return false;
        }
        return true;
    }

    /**
     * Perform a permission check.
     *
     * @param perm the permission to check
     * @param context the security context to use for the check
     * @throws SecurityException if the check fails
     */
    public void checkPermission(final Permission perm, final AccessControlContext context) throws SecurityException {
        if (perm.implies(SECURITY_MANAGER_PERMISSION)) {
            throw access.secMgrChange();
        }
        final Context ctx = CTX.get();
        if (ctx.checking) {
            if (ctx.entered) {
                return;
            }
            final ProtectionDomain[] stack;
            ctx.entered = true;
            try {
                stack = getProtectionDomainStack(context);
                if (stack != null) {
                    final ProtectionDomain deniedDomain = findAccessDenial(perm, stack);
                    if (deniedDomain != null) {
                        final CodeSource codeSource = deniedDomain.getCodeSource();
                        final ClassLoader classLoader = deniedDomain.getClassLoader();
                        final Principal[] principals = deniedDomain.getPrincipals();
                        if (principals == null || principals.length == 0) {
                            access.accessCheckFailed(perm, codeSource, classLoader);
                        } else {
                            access.accessCheckFailed(perm, codeSource, classLoader, Arrays.toString(principals));
                        }
                        throw access.accessControlException(perm, perm, codeSource, classLoader);
                    }
                }
            } finally {
                ctx.entered = false;
            }
        }
    }

    void checkPermission(final Permission perm, final Class<?> clazz) throws SecurityException {
        if (perm.implies(SECURITY_MANAGER_PERMISSION)) {
            throw access.secMgrChange();
        }
        final Context ctx = CTX.get();
        if (ctx.checking) {
            if (ctx.entered) {
                return;
            }
            final ProtectionDomain protectionDomain;
            ctx.entered = true;
            try {
                protectionDomain = clazz.getProtectionDomain();
                if (protectionDomain != null) {
                    if (! (protectionDomain.implies(perm))) {
                        final CodeSource codeSource = protectionDomain.getCodeSource();
                        final ClassLoader classLoader = protectionDomain.getClassLoader();
                        final Principal[] principals = protectionDomain.getPrincipals();
                        if (principals == null || principals.length == 0) {
                            access.accessCheckFailed(perm, codeSource, classLoader);
                        } else {
                            access.accessCheckFailed(perm, codeSource, classLoader, Arrays.toString(principals));
                        }
                        throw access.accessControlException(perm, perm, codeSource, classLoader);
                    }
                }
            } finally {
                ctx.entered = false;
            }
        }
    }

    private static ProtectionDomain[] getProtectionDomainStack(final AccessControlContext context) {
        final ProtectionDomain[] stack;
        try {
            stack = (ProtectionDomain[]) PD_STACK.get(context);
        } catch (IllegalAccessException e) {
            // should be impossible
            throw new IllegalAccessError(e.getMessage());
        }
        return stack;
    }

    private static boolean doCheck() {
        return doCheck(CTX.get());
    }

    private static boolean doCheck(final WildFlySecurityManager.Context ctx) {
        return ctx.checking && ! ctx.entered;
    }

    public void checkCreateClassLoader() {
        if (doCheck()) {
            super.checkCreateClassLoader();
        }
    }

    public void checkAccess(final Thread t) {
        if (doCheck()) {
            super.checkAccess(t);
        }
    }

    public void checkAccess(final ThreadGroup g) {
        if (doCheck()) {
            super.checkAccess(g);
        }
    }

    public void checkExit(final int status) {
        if (doCheck()) {
            super.checkExit(status);
        }
    }

    public void checkExec(final String cmd) {
        if (doCheck()) {
            super.checkExec(cmd);
        }
    }

    public void checkLink(final String lib) {
        if (doCheck()) {
            super.checkLink(lib);
        }
    }

    public void checkRead(final FileDescriptor fd) {
        if (doCheck()) {
            super.checkRead(fd);
        }
    }

    public void checkRead(final String file) {
        if (doCheck()) {
            super.checkRead(file);
        }
    }

    public void checkRead(final String file, final Object context) {
        if (doCheck()) {
            super.checkRead(file, context);
        }
    }

    public void checkWrite(final FileDescriptor fd) {
        if (doCheck()) {
            super.checkWrite(fd);
        }
    }

    public void checkWrite(final String file) {
        if (doCheck()) {
            super.checkWrite(file);
        }
    }

    public void checkDelete(final String file) {
        if (doCheck()) {
            super.checkDelete(file);
        }
    }

    public void checkConnect(final String host, final int port) {
        if (doCheck()) {
            super.checkConnect(host, port);
        }
    }

    public void checkConnect(final String host, final int port, final Object context) {
        if (doCheck()) {
            super.checkConnect(host, port, context);
        }
    }

    public void checkListen(final int port) {
        if (doCheck()) {
            super.checkListen(port);
        }
    }

    public void checkAccept(final String host, final int port) {
        if (doCheck()) {
            super.checkAccept(host, port);
        }
    }

    public void checkMulticast(final InetAddress maddr) {
        if (doCheck()) {
            super.checkMulticast(maddr);
        }
    }

    @Deprecated @SuppressWarnings("deprecation")
    public void checkMulticast(final InetAddress maddr, final byte ttl) {
        if (doCheck()) {
            super.checkMulticast(maddr, ttl);
        }
    }

    public void checkPropertiesAccess() {
        if (doCheck()) {
            super.checkPropertiesAccess();
        }
    }

    public void checkPropertyAccess(final String key) {
        final Context ctx = CTX.get();
        if (doCheck(ctx)) {
            /*
             * Here is our expected stack:
             *   0: this method
             *   1: java.lang.System.getProperty()
             *   2: user code   | java.lang.(Boolean|Integer|Long).getXxx()
             *  3+: ???         | java.lang.(Boolean|Integer|Long).getXxx() (more)
             *   n:             | user code
             */
            Class<?>[] context = getClassContext();
            if (context.length < 3) {
                super.checkPropertyAccess(key);
                return;
            }
            if (context[1] != System.class) {
                super.checkPropertyAccess(key);
                return;
            }
            Class<?> testClass = context[2];
            if (context.length >= 4) for (int i = 2; i < context.length; i ++) {
                if (context[i] == Boolean.class || context[i] == Integer.class || context[i] == Long.class) {
                    testClass = context[i + 1];
                } else {
                    break;
                }
            }
            final ProtectionDomain protectionDomain;
            final ClassLoader classLoader;
            final ClassLoader objectClassLoader;
            ctx.entered = true;
            try {
                protectionDomain = testClass.getProtectionDomain();
                classLoader = testClass.getClassLoader();
                objectClassLoader = Object.class.getClassLoader();
            } finally {
                ctx.entered = false;
            }
            if (classLoader == objectClassLoader) {
                // can't trust it, it's gone through more JDK code
                super.checkPropertyAccess(key);
                return;
            }
            final PropertyPermission permission = new PropertyPermission(key, "read");
            if (protectionDomain.implies(permission)) {
                return;
            }
            checkPermission(permission, AccessController.getContext());
        }
    }

    public void checkPrintJobAccess() {
        if (doCheck()) {
            super.checkPrintJobAccess();
        }
    }

    public void checkPackageAccess(final String pkg) {
        if (doCheck()) {
            super.checkPackageAccess(pkg);
        }
    }

    public void checkPackageDefinition(final String pkg) {
        if (doCheck()) {
            super.checkPackageDefinition(pkg);
        }
    }

    public void checkSetFactory() {
        if (doCheck()) {
            super.checkSetFactory();
        }
    }

    private static final Class<?>[] ATOMIC_FIELD_UPDATER_TYPES = new Class<?>[] {
        AtomicReferenceFieldUpdater.class, AtomicLongFieldUpdater.class, AtomicIntegerFieldUpdater.class
    };

    private static boolean isAssignableToOneOf(Class<?> test, Class<?>... expect) {
        for (Class<?> clazz : expect) {
            if (clazz.isAssignableFrom(test)) return true;
        }
        return false;
    }

    public void checkMemberAccess(final Class<?> clazz, final int which) {
        final Context ctx = CTX.get();
        if (doCheck(ctx)) {
            if (clazz == null) {
                throw new NullPointerException("class can't be null");
            }
            if (which != Member.PUBLIC) {
                /* The default sec mgr implementation makes some ugly assumptions about call stack depth that we must
                 * unfortunately replicate (and improve upon).  Here are the stack elements we expect to see:
                 *
                 *   0: this method
                 *   1: java.lang.Class#checkMemberAccess()
                 *   2: java.lang.Class#getDeclared*() or similar in Class
                 *   3: user code | java.util.concurrent.Atomic*FieldUpdater (impl)
                 *  4+: ???       | java.util.concurrent.Atomic*FieldUpdater (possibly more)
                 *   n: ???       | user code
                 *
                 * The great irony is that Class is supposed to detect that this method is overridden and fall back to
                 * a simple permission check, however that doesn't seem to be working in practice.
                 */
                Class<?>[] context = getClassContext();
                int depth = context.length;
                if (depth >= 4 && context[1] == Class.class && context[2] == Class.class) {
                    final ClassLoader objectClassLoader;
                    final ClassLoader clazzClassLoader;
                    ClassLoader classLoader;
                    // get class loaders without permission check
                    ctx.entered = true;
                    try {
                        objectClassLoader = Object.class.getClassLoader();
                        clazzClassLoader = clazz.getClassLoader();
                        for (int i = 3; i < depth; i ++) {
                            classLoader = context[i].getClassLoader();
                            if (classLoader == objectClassLoader) {
                                if (isAssignableToOneOf(context[i], ATOMIC_FIELD_UPDATER_TYPES)) {
                                    // keep going
                                } else {
                                    // unknown JDK class, fall back
                                    checkPermission(ACCESS_DECLARED_MEMBERS_PERMISSION);
                                    return;
                                }
                            } else {
                                if (clazzClassLoader == classLoader) {
                                    // permission granted
                                    return;
                                } else {
                                    // class loaders differ
                                    checkPermission(ACCESS_DECLARED_MEMBERS_PERMISSION);
                                    return;
                                }
                            }
                        }
                    } finally {
                        ctx.entered = false;
                    }
                }
                // fall back to paranoid check
                checkPermission(ACCESS_DECLARED_MEMBERS_PERMISSION);
            }
        }
    }

    public void checkSecurityAccess(final String target) {
        if (doCheck()) {
            super.checkSecurityAccess(target);
        }
    }

    /**
     * Perform an action with permission checking enabled.  If permission checking is already enabled, the action is
     * simply run.
     *
     * @param action the action to perform
     * @param <T> the action return type
     * @return the return value of the action
     */
    public static <T> T doChecked(PrivilegedAction<T> action) {
        final Context ctx = CTX.get();
        if (ctx.checking) {
            return action.run();
        }
        ctx.checking = true;
        try {
            return action.run();
        } finally {
            ctx.checking = false;
        }
    }

    /**
     * Perform an action with permission checking enabled.  If permission checking is already enabled, the action is
     * simply run.
     *
     * @param action the action to perform
     * @param <T> the action return type
     * @return the return value of the action
     * @throws PrivilegedActionException if the action threw an exception
     */
    public static <T> T doChecked(PrivilegedExceptionAction<T> action) throws PrivilegedActionException {
        final Context ctx = CTX.get();
        if (ctx.checking) {
            try {
                return action.run();
            } catch (RuntimeException e) {
                throw e;
            } catch (Exception e) {
                throw new PrivilegedActionException(e);
            }
        }
        ctx.checking = true;
        try {
            return action.run();
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new PrivilegedActionException(e);
        } finally {
            ctx.checking = false;
        }
    }

    /**
     * Perform an action with permission checking enabled.  If permission checking is already enabled, the action is
     * simply run.
     *
     * @param action the action to perform
     * @param context the access control context to use
     * @param <T> the action return type
     * @return the return value of the action
     */
    public static <T> T doChecked(PrivilegedAction<T> action, AccessControlContext context) {
        final Context ctx = CTX.get();
        if (ctx.checking) {
            return action.run();
        }
        ctx.checking = true;
        try {
            return AccessController.doPrivileged(action, context);
        } finally {
            ctx.checking = false;
        }
    }

    /**
     * Perform an action with permission checking enabled.  If permission checking is already enabled, the action is
     * simply run.
     *
     * @param action the action to perform
     * @param context the access control context to use
     * @param <T> the action return type
     * @return the return value of the action
     * @throws PrivilegedActionException if the action threw an exception
     */
    public static <T> T doChecked(PrivilegedExceptionAction<T> action, AccessControlContext context) throws PrivilegedActionException {
        final Context ctx = CTX.get();
        if (ctx.checking) {
            try {
                return action.run();
            } catch (RuntimeException e) {
                throw e;
            } catch (Exception e) {
                throw new PrivilegedActionException(e);
            }
        }
        ctx.checking = true;
        try {
            return AccessController.doPrivileged(action, context);
        } finally {
            ctx.checking = false;
        }
    }

    /**
     * Perform an action with permission checking enabled.  If permission checking is already enabled, the action is
     * simply run.
     *
     * @param parameter the parameter to pass to the action
     * @param action the action to perform
     * @param <T> the action return type
     * @param <P> the action parameter type
     * @return the return value of the action
     */
    public static <T, P> T doChecked(P parameter, ParametricPrivilegedAction<T, P> action) {
        final Context ctx = CTX.get();
        if (ctx.checking) {
            return action.run(parameter);
        }
        ctx.checking = true;
        try {
            return action.run(parameter);
        } finally {
            ctx.checking = false;
        }
    }

    /**
     * Perform an action with permission checking enabled.  If permission checking is already enabled, the action is
     * simply run.
     *
     * @param parameter the parameter to pass to the action
     * @param action the action to perform
     * @param <T> the action return type
     * @param <P> the action parameter type
     * @return the return value of the action
     * @throws PrivilegedActionException if the action threw an exception
     */
    public static <T, P> T doChecked(P parameter, ParametricPrivilegedExceptionAction<T, P> action) throws PrivilegedActionException {
        final Context ctx = CTX.get();
        if (ctx.checking) {
            try {
                return action.run(parameter);
            } catch (RuntimeException e) {
                throw e;
            } catch (Exception e) {
                throw new PrivilegedActionException(e);
            }
        }
        ctx.checking = true;
        try {
            return action.run(parameter);
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new PrivilegedActionException(e);
        } finally {
            ctx.checking = false;
        }
    }

    /**
     * Perform an action with permission checking enabled.  If permission checking is already enabled, the action is
     * simply run.
     *
     * @param parameter the parameter to pass to the action
     * @param action the action to perform
     * @param context the access control context to use
     * @param <T> the action return type
     * @param <P> the action parameter type
     * @return the return value of the action
     */
    public static <T, P> T doChecked(P parameter, ParametricPrivilegedAction<T, P> action, AccessControlContext context) {
        final Context ctx = CTX.get();
        if (ctx.checking) {
            return action.run(parameter);
        }
        ctx.checking = true;
        try {
            return doPrivilegedWithParameter(parameter, action, context);
        } finally {
            ctx.checking = false;
        }
    }

    /**
     * Perform an action with permission checking enabled.  If permission checking is already enabled, the action is
     * simply run.
     *
     * @param parameter the parameter to pass to the action
     * @param action the action to perform
     * @param context the access control context to use
     * @param <T> the action return type
     * @param <P> the action parameter type
     * @return the return value of the action
     * @throws PrivilegedActionException if the action threw an exception
     */
    public static <T, P> T doChecked(P parameter, ParametricPrivilegedExceptionAction<T, P> action, AccessControlContext context) throws PrivilegedActionException {
        final Context ctx = CTX.get();
        if (ctx.checking) {
            try {
                return action.run(parameter);
            } catch (RuntimeException e) {
                throw e;
            } catch (Exception e) {
                throw new PrivilegedActionException(e);
            }
        }
        ctx.checking = true;
        try {
            return doPrivilegedWithParameter(parameter, action, context);
        } finally {
            ctx.checking = false;
        }
    }

    /**
     * Perform an action with permission checking disabled.  If permission checking is already disabled, the action is
     * simply run.  The immediate caller must have the {@code doUnchecked} runtime permission.
     *
     * @param action the action to perform
     * @param <T> the action return type
     * @return the return value of the action
     */
    public static <T> T doUnchecked(PrivilegedAction<T> action) {
        final Context ctx = CTX.get();
        if (! ctx.checking) {
            return action.run();
        }
        ctx.checking = false;
        try {
            final SecurityManager sm = getSecurityManager();
            if (sm != null) {
                checkPDPermission(getCallerClass(2), DO_UNCHECKED_PERMISSION);
            }
            return action.run();
        } finally {
            ctx.checking = true;
        }
    }

    /**
     * Perform an action with permission checking disabled.  If permission checking is already disabled, the action is
     * simply run.  The caller must have the {@code doUnchecked} runtime permission.
     *
     * @param action the action to perform
     * @param <T> the action return type
     * @return the return value of the action
     * @throws PrivilegedActionException if the action threw an exception
     */
    public static <T> T doUnchecked(PrivilegedExceptionAction<T> action) throws PrivilegedActionException {
        final Context ctx = CTX.get();
        if (! ctx.checking) {
            try {
                return action.run();
            } catch (Exception e) {
                throw new PrivilegedActionException(e);
            }
        }
        ctx.checking = false;
        try {
            final SecurityManager sm = getSecurityManager();
            if (sm != null) {
                checkPDPermission(getCallerClass(2), DO_UNCHECKED_PERMISSION);
            }
            return action.run();
        } catch (Exception e) {
            throw new PrivilegedActionException(e);
        } finally {
            ctx.checking = true;
        }
    }

    /**
     * Perform an action with permission checking disabled.  If permission checking is already disabled, the action is
     * simply run.  The immediate caller must have the {@code doUnchecked} runtime permission.
     *
     * @param action the action to perform
     * @param context the access control context to use
     * @param <T> the action return type
     * @return the return value of the action
     */
    public static <T> T doUnchecked(PrivilegedAction<T> action, AccessControlContext context) {
        final Context ctx = CTX.get();
        if (! ctx.checking) {
            return AccessController.doPrivileged(action, context);
        }
        ctx.checking = false;
        try {
            final SecurityManager sm = getSecurityManager();
            if (sm != null) {
                checkPDPermission(getCallerClass(2), DO_UNCHECKED_PERMISSION);
            }
            return AccessController.doPrivileged(action, context);
        } finally {
            ctx.checking = true;
        }
    }

    /**
     * Perform an action with permission checking disabled.  If permission checking is already disabled, the action is
     * simply run.  The caller must have the {@code doUnchecked} runtime permission.
     *
     * @param action the action to perform
     * @param context the access control context to use
     * @param <T> the action return type
     * @return the return value of the action
     * @throws PrivilegedActionException if the action threw an exception
     */
    public static <T> T doUnchecked(PrivilegedExceptionAction<T> action, AccessControlContext context) throws PrivilegedActionException {
        final Context ctx = CTX.get();
        if (! ctx.checking) {
            return AccessController.doPrivileged(action, context);
        }
        ctx.checking = false;
        try {
            final SecurityManager sm = getSecurityManager();
            if (sm != null) {
                checkPDPermission(getCallerClass(2), DO_UNCHECKED_PERMISSION);
            }
            return AccessController.doPrivileged(action, context);
        } finally {
            ctx.checking = true;
        }
    }

    /**
     * Perform an action with permission checking disabled.  If permission checking is already disabled, the action is
     * simply run.  The immediate caller must have the {@code doUnchecked} runtime permission.
     *
     * @param parameter the parameter to pass to the action
     * @param action the action to perform
     * @param <T> the action return type
     * @param <P> the action parameter type
     * @return the return value of the action
     */
    public static <T, P> T doUnchecked(P parameter, ParametricPrivilegedAction<T, P> action) {
        final Context ctx = CTX.get();
        if (! ctx.checking) {
            return action.run(parameter);
        }
        ctx.checking = false;
        try {
            final SecurityManager sm = getSecurityManager();
            if (sm != null) {
                checkPDPermission(getCallerClass(2), DO_UNCHECKED_PERMISSION);
            }
            return action.run(parameter);
        } finally {
            ctx.checking = true;
        }
    }

    /**
     * Perform an action with permission checking disabled.  If permission checking is already disabled, the action is
     * simply run.  The caller must have the {@code doUnchecked} runtime permission.
     *
     * @param parameter the parameter to pass to the action
     * @param action the action to perform
     * @param <T> the action return type
     * @param <P> the action parameter type
     * @return the return value of the action
     * @throws PrivilegedActionException if the action threw an exception
     */
    public static <T, P> T doUnchecked(P parameter, ParametricPrivilegedExceptionAction<T, P> action) throws PrivilegedActionException {
        final Context ctx = CTX.get();
        if (! ctx.checking) {
            try {
                return action.run(parameter);
            } catch (Exception e) {
                throw new PrivilegedActionException(e);
            }
        }
        ctx.checking = false;
        try {
            final SecurityManager sm = getSecurityManager();
            if (sm != null) {
                checkPDPermission(getCallerClass(2), DO_UNCHECKED_PERMISSION);
            }
            return action.run(parameter);
        } catch (Exception e) {
            throw new PrivilegedActionException(e);
        } finally {
            ctx.checking = true;
        }
    }

    /**
     * Perform an action with permission checking disabled.  If permission checking is already disabled, the action is
     * simply run.  The immediate caller must have the {@code doUnchecked} runtime permission.
     *
     * @param parameter the parameter to pass to the action
     * @param action the action to perform
     * @param context the access control context to use
     * @param <T> the action return type
     * @param <P> the action parameter type
     * @return the return value of the action
     */
    public static <T, P> T doUnchecked(P parameter, ParametricPrivilegedAction<T, P> action, AccessControlContext context) {
        final Context ctx = CTX.get();
        if (! ctx.checking) {
            return doPrivilegedWithParameter(parameter, action, context);
        }
        ctx.checking = false;
        try {
            final SecurityManager sm = getSecurityManager();
            if (sm != null) {
                checkPDPermission(getCallerClass(2), DO_UNCHECKED_PERMISSION);
            }
            return doPrivilegedWithParameter(parameter, action, context);
        } finally {
            ctx.checking = true;
        }
    }

    /**
     * Perform an action with permission checking disabled.  If permission checking is already disabled, the action is
     * simply run.  The caller must have the {@code doUnchecked} runtime permission.
     *
     * @param parameter the parameter to pass to the action
     * @param action the action to perform
     * @param context the access control context to use
     * @param <T> the action return type
     * @param <P> the action parameter type
     * @return the return value of the action
     * @throws PrivilegedActionException if the action threw an exception
     */
    public static <T, P> T doUnchecked(P parameter, ParametricPrivilegedExceptionAction<T, P> action, AccessControlContext context) throws PrivilegedActionException {
        final Context ctx = CTX.get();
        if (! ctx.checking) {
            return doPrivilegedWithParameter(parameter, action, context);
        }
        ctx.checking = false;
        try {
            final SecurityManager sm = getSecurityManager();
            if (sm != null) {
                checkPDPermission(getCallerClass(2), DO_UNCHECKED_PERMISSION);
            }
            return doPrivilegedWithParameter(parameter, action, context);
        } finally {
            ctx.checking = true;
        }
    }

    private static void checkPropertyReadPermission(Class<?> clazz, String propertyName) {
        final ProtectionDomain protectionDomain;
        final ClassLoader classLoader;
        if (getSecurityManager() instanceof WildFlySecurityManager) {
            protectionDomain = clazz.getProtectionDomain();
            classLoader = clazz.getClassLoader();
        } else {
            protectionDomain = doPrivileged(new GetProtectionDomainAction(clazz));
            classLoader = doPrivileged(new GetClassLoaderAction(clazz));
        }
        if (protectionDomain.implies(PROPERTIES_PERMISSION)) {
            return;
        }
        final PropertyPermission permission = new PropertyPermission(propertyName, "read");
        if (protectionDomain.implies(permission)) {
            return;
        }
        access.accessCheckFailed(permission, protectionDomain.getCodeSource(), classLoader);
        throw access.accessControlException(permission, permission, protectionDomain.getCodeSource(), classLoader);
    }

    private static void checkEnvPropertyReadPermission(Class<?> clazz, String propertyName) {
        final ProtectionDomain protectionDomain;
        final ClassLoader classLoader;
        if (getSecurityManager() instanceof WildFlySecurityManager) {
            protectionDomain = clazz.getProtectionDomain();
            classLoader = clazz.getClassLoader();
        } else {
            protectionDomain = doPrivileged(new GetProtectionDomainAction(clazz));
            classLoader = doPrivileged(new GetClassLoaderAction(clazz));
        }
        if (protectionDomain.implies(ENVIRONMENT_PERMISSION)) {
            return;
        }
        final RuntimePermission permission = new RuntimePermission("getenv." + propertyName);
        if (protectionDomain.implies(permission)) {
            return;
        }
        access.accessCheckFailed(permission, protectionDomain.getCodeSource(), classLoader);
        throw access.accessControlException(permission, permission, protectionDomain.getCodeSource(), classLoader);
    }

    private static void checkPropertyWritePermission(Class<?> clazz, String propertyName) {
        final ProtectionDomain protectionDomain;
        final ClassLoader classLoader;
        if (getSecurityManager() instanceof WildFlySecurityManager) {
            protectionDomain = clazz.getProtectionDomain();
            classLoader = clazz.getClassLoader();
        } else {
            protectionDomain = doPrivileged(new GetProtectionDomainAction(clazz));
            classLoader = doPrivileged(new GetClassLoaderAction(clazz));
        }
        if (protectionDomain.implies(PROPERTIES_PERMISSION)) {
            return;
        }
        final PropertyPermission permission = new PropertyPermission(propertyName, "write");
        if (protectionDomain.implies(permission)) {
            return;
        }
        access.accessCheckFailed(permission, protectionDomain.getCodeSource(), classLoader);
        throw access.accessControlException(permission, permission, protectionDomain.getCodeSource(), classLoader);
    }

    private static void checkPDPermission(Class<?> clazz, Permission permission) {
        final ProtectionDomain protectionDomain;
        final ClassLoader classLoader;
        if (getSecurityManager() instanceof WildFlySecurityManager) {
            protectionDomain = clazz.getProtectionDomain();
            classLoader = clazz.getClassLoader();
        } else {
            protectionDomain = doPrivileged(new GetProtectionDomainAction(clazz));
            classLoader = doPrivileged(new GetClassLoaderAction(clazz));
        }
        if (protectionDomain.implies(permission)) {
            return;
        }
        access.accessCheckFailed(permission, protectionDomain.getCodeSource(), classLoader);
        throw access.accessControlException(permission, permission, protectionDomain.getCodeSource(), classLoader);
    }

    /**
     * Get a property, doing a faster permission check that skips having to execute a privileged action frame.
     *
     * @param name the property name
     * @param def the default value if the property is not found
     * @return the property value, or the default value
     */
    public static String getPropertyPrivileged(String name, String def) {
        final SecurityManager sm = getSecurityManager();
        if (sm == null) {
            return getProperty(name, def);
        }
        if (sm instanceof WildFlySecurityManager) {
            final Context ctx = CTX.get();
            if (! ctx.checking) {
                return getProperty(name, def);
            }
            ctx.checking = false;
            try {
                checkPropertyReadPermission(getCallerClass(2), name);
                return getProperty(name, def);
            } finally {
                ctx.checking = true;
            }
        } else {
            checkPropertyReadPermission(getCallerClass(2), name);
            return doPrivileged(new ReadPropertyAction(name, def));
        }
    }

    private static <T> T def(T test, T def) {
        return test == null ? def : test;
    }

    /**
     * Get an environmental property, doing a faster permission check that skips having to execute a privileged action frame.
     *
     * @param name the property name
     * @param def the default value if the property is not found
     * @return the property value, or the default value
     */
    public static String getEnvPropertyPrivileged(String name, String def) {
        final SecurityManager sm = getSecurityManager();
        if (sm == null) {
            return getenv(name);
        }
        if (sm instanceof WildFlySecurityManager) {
            final Context ctx = CTX.get();
            if (! ctx.checking) {
                return def(getenv(name), def);
            }
            ctx.checking = false;
            try {
                checkEnvPropertyReadPermission(getCallerClass(2), name);
                return def(getenv(name), def);
            } finally {
                ctx.checking = true;
            }
        } else {
            checkEnvPropertyReadPermission(getCallerClass(2), name);
            return doPrivileged(new ReadEnvironmentPropertyAction(name, def));
        }
    }

    /**
     * Set a property, doing a faster permission check that skips having to execute a privileged action frame.
     *
     * @param name the property name
     * @param value the value ot set
     * @return the previous property value, or {@code null} if there was none
     */
    public static String setPropertyPrivileged(String name, String value) {
        final SecurityManager sm = getSecurityManager();
        if (sm == null) {
            return setProperty(name, value);
        }
        if (sm instanceof WildFlySecurityManager) {
            final Context ctx = CTX.get();
            if (! ctx.checking) {
                return setProperty(name, value);
            }
            ctx.checking = false;
            try {
                checkPropertyWritePermission(getCallerClass(2), name);
                return setProperty(name, value);
            } finally {
                ctx.checking = true;
            }
        } else {
            checkPropertyWritePermission(getCallerClass(2), name);
            return doPrivileged(new WritePropertyAction(name, value));
        }
    }

    /**
     * Clear a property, doing a faster permission check that skips having to execute a privileged action frame.
     *
     * @param name the property name
     * @return the previous property value, or {@code null} if there was none
     */
    public static String clearPropertyPrivileged(String name) {
        final SecurityManager sm = getSecurityManager();
        if (sm == null) {
            return clearProperty(name);
        }
        if (sm instanceof WildFlySecurityManager) {
            final Context ctx = CTX.get();
            if (! ctx.checking) {
                return clearProperty(name);
            }
            ctx.checking = false;
            try {
                checkPropertyWritePermission(getCallerClass(2), name);
                return clearProperty(name);
            } finally {
                ctx.checking = true;
            }
        } else {
            checkPropertyWritePermission(getCallerClass(2), name);
            return doPrivileged(new ClearPropertyAction(name));
        }
    }

    /**
     * Get the current thread's context class loader, doing a faster permission check that skips having to execute a
     * privileged action frame.
     *
     * @return the context class loader
     */
    public static ClassLoader getCurrentContextClassLoaderPrivileged() {
        final SecurityManager sm = System.getSecurityManager();
        if (sm == null) {
            return currentThread().getContextClassLoader();
        }
        if (sm instanceof WildFlySecurityManager) {
            final Context ctx = CTX.get();
            if (! ctx.checking) {
                return currentThread().getContextClassLoader();
            }
            ctx.checking = false;
            try {
                checkPDPermission(getCallerClass(2), GET_CLASS_LOADER_PERMISSION);
                return currentThread().getContextClassLoader();
            } finally {
                ctx.checking = true;
            }
        } else {
            checkPDPermission(getCallerClass(2), GET_CLASS_LOADER_PERMISSION);
            return doPrivileged(GetContextClassLoaderAction.getInstance());
        }
    }

    /**
     * Set the current thread's context class loader, doing a faster permission check that skips having to execute a
     * privileged action frame.
     *
     * @param newClassLoader the new class loader to set
     * @return the previously set context class loader
     */
    public static ClassLoader setCurrentContextClassLoaderPrivileged(ClassLoader newClassLoader) {
        final SecurityManager sm = System.getSecurityManager();
        final Thread thread = currentThread();
        if (sm == null) try {
            return thread.getContextClassLoader();
        } finally {
            thread.setContextClassLoader(newClassLoader);
        }
        if (sm instanceof WildFlySecurityManager) {
            final Context ctx = CTX.get();
            if (! ctx.checking) try {
                return thread.getContextClassLoader();
            } finally {
                thread.setContextClassLoader(newClassLoader);
            }
            ctx.checking = false;
            // separate try/finally to guarantee proper exception flow
            try {
                checkPDPermission(getCallerClass(2), SET_CLASS_LOADER_PERMISSION);
                try {
                    return thread.getContextClassLoader();
                } finally {
                    thread.setContextClassLoader(newClassLoader);
                }
            } finally {
                ctx.checking = true;
            }
        } else {
            checkPDPermission(getCallerClass(2), SET_CLASS_LOADER_PERMISSION);
            return doPrivileged(new SetContextClassLoaderAction(newClassLoader));
        }
    }

    /**
     * Set the current thread's context class loader, doing a faster permission check that skips having to execute a
     * privileged action frame.
     *
     * @param clazz the class whose class loader is the new class loader to set
     * @return the previously set context class loader
     */
    public static ClassLoader setCurrentContextClassLoaderPrivileged(final Class<?> clazz) {
        final SecurityManager sm = System.getSecurityManager();
        final Thread thread = currentThread();
        if (sm == null) try {
            return thread.getContextClassLoader();
        } finally {
            thread.setContextClassLoader(clazz.getClassLoader());
        }
        if (sm instanceof WildFlySecurityManager) {
            final Context ctx = CTX.get();
            if (! ctx.checking) try {
                return thread.getContextClassLoader();
            } finally {
                thread.setContextClassLoader(clazz.getClassLoader());
            }
            ctx.checking = false;
            // separate try/finally to guarantee proper exception flow
            try {
                final Class<?> caller = getCallerClass(2);
                checkPDPermission(caller, SET_CLASS_LOADER_PERMISSION);
                checkPDPermission(caller, GET_CLASS_LOADER_PERMISSION);
                try {
                    return thread.getContextClassLoader();
                } finally {
                    thread.setContextClassLoader(clazz.getClassLoader());
                }
            } finally {
                ctx.checking = true;
            }
        } else {
            final Class<?> caller = getCallerClass(2);
            checkPDPermission(caller, SET_CLASS_LOADER_PERMISSION);
            checkPDPermission(caller, GET_CLASS_LOADER_PERMISSION);
            return doPrivileged(new SetContextClassLoaderAction(clazz.getClassLoader()));
        }
    }

    /**
     * Get the system properties map, doing a faster permission check that skips having to execute a privileged action
     * frame.
     *
     * @return the system property map
     */
    public static Properties getSystemPropertiesPrivileged() {
        final SecurityManager sm = System.getSecurityManager();
        if (sm == null) {
            return getProperties();
        }
        if (sm instanceof WildFlySecurityManager) {
            final Context ctx = CTX.get();
            if (! ctx.checking) {
                return getProperties();
            }
            ctx.checking = false;
            try {
                checkPDPermission(getCallerClass(2), PROPERTIES_PERMISSION);
                return getProperties();
            } finally {
                ctx.checking = true;
            }
        } else {
            checkPDPermission(getCallerClass(2), PROPERTIES_PERMISSION);
            return doPrivileged(GetSystemPropertiesAction.getInstance());
        }
    }

    /**
     * Get the system environment map, doing a faster permission check that skips having to execute a privileged action
     * frame.
     *
     * @return the system environment map
     */
    public static Map<String, String> getSystemEnvironmentPrivileged() {
        final SecurityManager sm = System.getSecurityManager();
        if (sm == null) {
            return getenv();
        }
        if (sm instanceof WildFlySecurityManager) {
            final Context ctx = CTX.get();
            if (! ctx.checking) {
                return getenv();
            }
            ctx.checking = false;
            try {
                checkPDPermission(getCallerClass(2), ENVIRONMENT_PERMISSION);
                return getenv();
            } finally {
                ctx.checking = true;
            }
        } else {
            checkPDPermission(getCallerClass(2), ENVIRONMENT_PERMISSION);
            return doPrivileged(GetEnvironmentAction.getInstance());
        }
    }

    /**
     * Get the class loader for a class, doing a faster permission check that skips having to execute a privileged action
     * frame.
     *
     * @param clazz the class to check
     * @return the class loader
     */
    public static ClassLoader getClassLoaderPrivileged(Class<?> clazz) {
        final SecurityManager sm = System.getSecurityManager();
        if (sm == null) {
            return clazz.getClassLoader();
        }
        if (sm instanceof WildFlySecurityManager) {
            final Context ctx = CTX.get();
            if (! ctx.checking) {
                return clazz.getClassLoader();
            }
            ctx.checking = false;
            try {
                checkPDPermission(getCallerClass(2), GET_CLASS_LOADER_PERMISSION);
                return clazz.getClassLoader();
            } finally {
                ctx.checking = true;
            }
        } else {
            checkPDPermission(getCallerClass(2), GET_CLASS_LOADER_PERMISSION);
            return doPrivileged(new GetClassLoaderAction(clazz));
        }
    }

    private static final ClassValue<AccessControlContext> ACC_CACHE = new ClassValue<AccessControlContext>() {
        protected AccessControlContext computeValue(final Class<?> type) {
            final Context ctx = CTX.get();
            assert ! ctx.entered;
            ctx.entered = true;
            try {
                return new AccessControlContext(new ProtectionDomain[] { type.getProtectionDomain() });
            } finally {
                ctx.entered = false;
            }
        }
    };

    private static final PrivilegedAction<Object> PA_TRAMPOLINE1 = new PrivilegedAction<Object>() {
        public Object run() {
            final Context ctx = CTX.get();
            final ParametricPrivilegedAction<Object, Object> a = ctx.action1;
            final Object p = ctx.parameter;
            ctx.action1 = null;
            ctx.parameter = null;
            return a.run(p);
        }
    };

    private static final PrivilegedExceptionAction<Object> PA_TRAMPOLINE2 = new PrivilegedExceptionAction<Object>() {
        public Object run() throws Exception {
            final Context ctx = CTX.get();
            final ParametricPrivilegedExceptionAction<Object, Object> a = ctx.action2;
            final Object p = ctx.parameter;
            ctx.action2 = null;
            ctx.parameter = null;
            return a.run(p);
        }
    };

    /**
     * Execute a parametric privileged action with the given parameter in a privileged context.
     *
     * @param parameter the parameter to send in to the action
     * @param action the action to execute
     * @param <T> the action result type
     * @param <P> the parameter type
     * @return the action result
     */
    @SuppressWarnings("unchecked")
    public static <T, P> T doPrivilegedWithParameter(P parameter, ParametricPrivilegedAction<T, P> action) {
        final Context ctx = CTX.get();
        ctx.action1 = (ParametricPrivilegedAction<Object, Object>) action;
        ctx.parameter = parameter;
        return (T) doPrivileged(PA_TRAMPOLINE1, ACC_CACHE.get(getCallerClass(2)));
    }

    /**
     * Execute a parametric privileged action with the given parameter in a privileged context.
     *
     * @param parameter the parameter to send in to the action
     * @param action the action to execute
     * @param <T> the action result type
     * @param <P> the parameter type
     * @return the action result
     */
    @SuppressWarnings("unchecked")
    public static <T, P> T doPrivilegedWithParameter(P parameter, ParametricPrivilegedExceptionAction<T, P> action) throws PrivilegedActionException {
        final Context ctx = CTX.get();
        ctx.action2 = (ParametricPrivilegedExceptionAction<Object, Object>) action;
        ctx.parameter = parameter;
        return (T) doPrivileged(PA_TRAMPOLINE2, ACC_CACHE.get(getCallerClass(2)));
    }

    /**
     * Execute a parametric privileged action with the given parameter with the given context.
     *
     * @param parameter the parameter to send in to the action
     * @param action the action to execute
     * @param accessControlContext the context to use
     * @param <T> the action result type
     * @param <P> the parameter type
     * @return the action result
     */
    @SuppressWarnings("unchecked")
    public static <T, P> T doPrivilegedWithParameter(P parameter, ParametricPrivilegedAction<T, P> action, AccessControlContext accessControlContext) {
        final Context ctx = CTX.get();
        ctx.action1 = (ParametricPrivilegedAction<Object, Object>) action;
        ctx.parameter = parameter;
        ctx.entered = true;
        final AccessControlContext combined;
        try {
            ProtectionDomain[] protectionDomainStack = getProtectionDomainStack(accessControlContext);
            if (protectionDomainStack == null || protectionDomainStack.length == 0) {
                combined = ACC_CACHE.get(getCallerClass(2));
            } else {
                final ProtectionDomain[] finalDomains = Arrays.copyOf(protectionDomainStack, protectionDomainStack.length + 1);
                finalDomains[protectionDomainStack.length] = getCallerClass(2).getProtectionDomain();
                combined = new AccessControlContext(finalDomains);
            }
        } finally {
            ctx.entered = false;
        }
        return (T) doPrivileged(PA_TRAMPOLINE1, combined);
    }

    /**
     * Execute a parametric privileged action with the given parameter with the given context.
     *
     * @param parameter the parameter to send in to the action
     * @param action the action to execute
     * @param accessControlContext the context to use
     * @param <T> the action result type
     * @param <P> the parameter type
     * @return the action result
     */
    @SuppressWarnings("unchecked")
    public static <T, P> T doPrivilegedWithParameter(P parameter, ParametricPrivilegedExceptionAction<T, P> action, AccessControlContext accessControlContext) throws PrivilegedActionException {
        final Context ctx = CTX.get();
        ctx.action2 = (ParametricPrivilegedExceptionAction<Object, Object>) action;
        ctx.parameter = parameter;
        ctx.entered = true;
        final AccessControlContext combined;
        try {
            ProtectionDomain[] protectionDomainStack = getProtectionDomainStack(accessControlContext);
            if (protectionDomainStack == null || protectionDomainStack.length == 0) {
                combined = ACC_CACHE.get(getCallerClass(2));
            } else {
                final ProtectionDomain[] finalDomains = Arrays.copyOf(protectionDomainStack, protectionDomainStack.length + 1);
                finalDomains[protectionDomainStack.length] = getCallerClass(2).getProtectionDomain();
                combined = new AccessControlContext(finalDomains);
            }
        } finally {
            ctx.entered = false;
        }
        return (T) doPrivileged(PA_TRAMPOLINE2, combined);
    }
}
