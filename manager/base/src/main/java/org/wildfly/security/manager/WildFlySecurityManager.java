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

import java.io.FileDescriptor;
import java.lang.reflect.Field;
import java.lang.reflect.Member;
import java.net.InetAddress;
import java.security.AccessControlContext;
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
import org.wildfly.common.Assert;
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
import org.wildfly.security.permission.PermissionVerifier;
import sun.misc.Unsafe;

import static java.lang.System.clearProperty;
import static java.lang.System.getProperties;
import static java.lang.System.getProperty;
import static java.lang.System.getSecurityManager;
import static java.lang.System.getenv;
import static java.lang.System.setProperty;
import static java.lang.Thread.currentThread;
import static java.security.AccessController.doPrivileged;
import static java.security.AccessController.getContext;
import static org.wildfly.security.manager.WildFlySecurityManagerPermission.doUncheckedPermission;
import static org.wildfly.security.manager._private.SecurityMessages.access;

/**
 * The security manager.  This security manager implementation can be switched on and off on a per-thread basis,
 * and additionally logs access violations in a way that should be substantially clearer than most JDK implementations.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
@MetaInfServices(SecurityManager.class)
public final class WildFlySecurityManager extends SecurityManager implements PermissionVerifier {

    private static final Permission SECURITY_MANAGER_PERMISSION = new RuntimePermission("setSecurityManager");
    private static final Permission PROPERTIES_PERMISSION = new PropertyPermission("*", "read,write");
    private static final Permission ENVIRONMENT_PERMISSION = new RuntimePermission("getenv.*");
    private static final Permission GET_CLASS_LOADER_PERMISSION = new RuntimePermission("getClassLoader");
    private static final Permission SET_CLASS_LOADER_PERMISSION = new RuntimePermission("setClassLoader");
    private static final Permission ACCESS_DECLARED_MEMBERS_PERMISSION = new RuntimePermission("accessDeclaredMembers");

    private static final boolean LOG_ONLY;

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

    private static final Unsafe unsafe;
    private static final long pdStackOffset;
    private static final WildFlySecurityManager INSTANCE;
    private static final boolean hasGetCallerClass;
    private static final boolean usingStackWalker;

    static {
        final Field pdField;
        try {
            // does not need to be accessible
            pdField = AccessControlContext.class.getDeclaredField("context");
        } catch (NoSuchFieldException e) {
            throw new NoSuchFieldError(e.getMessage());
        }
        if (pdField.getType() != ProtectionDomain[].class) {
            throw new Error();
        }
        try {
            unsafe = (Unsafe) doPrivileged(new GetAccessibleDeclaredFieldAction(Unsafe.class, "theUnsafe")).get(null);
        } catch (IllegalAccessException e) {
            throw new IllegalAccessError(e.getMessage());
        }
        pdStackOffset = unsafe.objectFieldOffset(pdField);
        // Cannot be lambda due to JDK race conditions
        //noinspection Convert2Lambda,Anonymous2MethodRef
        INSTANCE = doPrivileged(new PrivilegedAction<WildFlySecurityManager>() {
            public WildFlySecurityManager run() {
                return new WildFlySecurityManager();
            }
        });
        boolean result = false;
        try {
            /*
             * If JDKSpecific.getCallerClass(0) does not return this class assume a fault and fall back to using
             * SecurityManager.getClassContext().
             */
            result = JDKSpecific.getCallerClass(0) == WildFlySecurityManager.class;
        } catch (Throwable ignored) {}
        hasGetCallerClass = result;
        usingStackWalker = hasGetCallerClass && JDKSpecific.usingStackWalker();
        LOG_ONLY = Boolean.parseBoolean(doPrivileged(new ReadPropertyAction("org.wildfly.security.manager.log-only", "false")));
    }

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
            /*
             * An additional 1 is added to take into account the call to.
             *   WildFlySecurityManager.getCallerClass(int);
             *
             * The individual JDKSpecific.getCallerClass(int) implementations take care
             * of any offset they require.
             */
            return JDKSpecific.getCallerClass(n + 1);
        } else {
            /*
             * Fixed offset of 2 to take into account the following calls on the call stack: -
             *   WildFlySecurityManager.getCallStack();
             *   WildFlySecurityManager.getCallerClass(int);
             */
            return getCallStack()[n + 2];
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
        checkPermission(perm, getContext());
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
        ProtectionDomain deniedDomain = null;
        if (domains != null) for (ProtectionDomain domain : domains) {
            if (! domain.implies(permission)) {
                final CodeSource codeSource = domain.getCodeSource();
                final ClassLoader classLoader = domain.getClassLoader();
                final Principal[] principals = domain.getPrincipals();
                if (principals == null || principals.length == 0) {
                    access.accessCheckFailed(permission, codeSource, classLoader);
                } else {
                    access.accessCheckFailed(permission, codeSource, classLoader, Arrays.toString(principals));
                }
                if (access.isTraceEnabled()) {
                    access.trace(
                            "Permission check failed (permission \"" + permission + "\" in protection domain " + domain + " )",
                            new RuntimeException("Exception not thrown, analysis only."));
                }
                if (deniedDomain == null && ! LOG_ONLY) {
                    deniedDomain = domain;
                }
            }
        }
        return deniedDomain;
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
        if (permission.implies(SECURITY_MANAGER_PERMISSION)) {
            return false;
        }
        final Context ctx = CTX.get();
        if (ctx.checking) {
            if (ctx.entered) {
                return true;
            }
            ctx.entered = true;
            try {
                final ProtectionDomain deniedDomain = findAccessDenial(permission, domains);
                if (deniedDomain != null) {
                    return false;
                }
            } finally {
                ctx.entered = false;
            }
        }
        return true;
    }

    public boolean implies(final Permission permission) {
        return tryCheckPermission(permission, getProtectionDomainStack(getContext()));
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
                        throw access.accessControlException(perm, perm, deniedDomain.getCodeSource(), deniedDomain.getClassLoader());
                    }
                }
            } finally {
                ctx.entered = false;
            }
        }
    }

    private static ProtectionDomain[] getProtectionDomainStack(final AccessControlContext context) {
        return (ProtectionDomain[]) unsafe.getObject(context, pdStackOffset);
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
             *   1: java.lang.System.getProperty() (may repeat)
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
                if (context[i] == Boolean.class || context[i] == Integer.class || context[i] == Long.class || context[i] == System.class) {
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
            checkPermission(permission, getContext());
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

    @Deprecated @SuppressWarnings("deprecation")
    public void checkMemberAccess(final Class<?> clazz, final int which) {
        final Context ctx = CTX.get();
        if (doCheck(ctx)) {
            Assert.checkNotNullParam("class", clazz);
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
            return doPrivileged(action, context);
        }
        ctx.checking = true;
        try {
            return doPrivileged(action, context);
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
                return doPrivileged(action, context);
            } catch (RuntimeException e) {
                throw e;
            } catch (Exception e) {
                throw new PrivilegedActionException(e);
            }
        }
        ctx.checking = true;
        try {
            return doPrivileged(action, context);
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
            return doPrivilegedWithParameter(parameter, action, context);
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
            return doPrivilegedWithParameter(parameter, action, context);
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
        final SecurityManager sm = getSecurityManager();
        if (sm instanceof WildFlySecurityManager) {
            final Context ctx = CTX.get();
            if (! ctx.checking) {
                return action.run();
            }
            ctx.checking = false;
            try {
                if (sm != null) {
                    checkPDPermission(getCallerClass(1), doUncheckedPermission);
                }
                return action.run();
            } finally {
                ctx.checking = true;
            }
        } else if (sm != null) {
            // Just doPrivileged as the caller.
            return doPrivileged(action, getCallerAccessControlContext());
        }

        return action.run();
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
        final SecurityManager sm = getSecurityManager();
        if (sm instanceof WildFlySecurityManager) {
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
                if (sm != null) {
                    checkPDPermission(getCallerClass(1), doUncheckedPermission);
                }
                return action.run();
            } catch (Exception e) {
                throw new PrivilegedActionException(e);
            } finally {
                ctx.checking = true;
            }
        } else if (sm != null) {
            // Just doPrivileged as the caller.
            return doPrivileged(action, getCallerAccessControlContext());
        }

        try {
            return action.run();
        } catch (Exception e) {
            throw new PrivilegedActionException(e);
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
        final SecurityManager sm = getSecurityManager();
        if (sm instanceof WildFlySecurityManager) {
            final Context ctx = CTX.get();
            if (! ctx.checking) {
                return doPrivileged(action, context);
            }
            ctx.checking = false;
            try {
                if (sm != null) {
                    checkPDPermission(getCallerClass(1), doUncheckedPermission);
                }
                return action.run();
            } finally {
                ctx.checking = true;
            }
        } else if (sm != null) {
            // Just doPrivileged as the caller.
            return doPrivileged(action, context);
        }

        return doPrivileged(action, context);
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
        final SecurityManager sm = getSecurityManager();
        if (sm instanceof WildFlySecurityManager) {
            final Context ctx = CTX.get();
            if (! ctx.checking) {
                return doPrivileged(action, context);
            }
            ctx.checking = false;
            try {
                if (sm != null) {
                    checkPDPermission(getCallerClass(1), doUncheckedPermission);
                }
                return doPrivileged(action, context);
            } finally {
                ctx.checking = true;
            }
        } else if (sm != null) {
            // Just doPrivileged as the caller.
            return doPrivileged(action, context);
        }

        return doPrivileged(action, context);
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
        final SecurityManager sm = getSecurityManager();
        if (sm instanceof WildFlySecurityManager) {
            final Context ctx = CTX.get();
            if (! ctx.checking) {
                return action.run(parameter);
            }
            ctx.checking = false;
            try {
                if (sm != null) {
                    checkPDPermission(getCallerClass(1), doUncheckedPermission);
                }
                return action.run(parameter);
            } finally {
                ctx.checking = true;
            }
        } else if (sm != null) {
            // Just doPrivileged as the caller.
            return doPrivilegedWithParameter(parameter, action, null);
        }

        return action.run(parameter);
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
        final SecurityManager sm = getSecurityManager();
        if (sm instanceof WildFlySecurityManager) {
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
                if (sm != null) {
                    checkPDPermission(getCallerClass(1), doUncheckedPermission);
                }
                return action.run(parameter);
            } catch (Exception e) {
                throw new PrivilegedActionException(e);
            } finally {
                ctx.checking = true;
            }
        } else if (sm != null) {
            // Just doPrivileged as the caller.
            return doPrivilegedWithParameter(parameter, action, null);
        }

        try {
            return action.run(parameter);
        } catch (Exception e) {
            throw new PrivilegedActionException(e);
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
        final SecurityManager sm = getSecurityManager();
        if (sm instanceof WildFlySecurityManager) {
            final Context ctx = CTX.get();
            if (! ctx.checking) {
                return doPrivilegedWithParameter(parameter, action, context);
            }
            ctx.checking = false;
            try {
                if (sm != null) {
                    checkPDPermission(getCallerClass(1), doUncheckedPermission);
                }
                return doPrivilegedWithParameter(parameter, action, context);
            } finally {
                ctx.checking = true;
            }
        }

        return doPrivilegedWithParameter(parameter, action, context);
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
        final SecurityManager sm = getSecurityManager();
        if (sm instanceof WildFlySecurityManager) {
            final Context ctx = CTX.get();
            if (! ctx.checking) {
                return doPrivilegedWithParameter(parameter, action, context);
            }
            ctx.checking = false;
            try {
                if (sm != null) {
                    checkPDPermission(getCallerClass(1), doUncheckedPermission);
                }
                return doPrivilegedWithParameter(parameter, action, context);
            } finally {
                ctx.checking = true;
            }
        }

        return doPrivilegedWithParameter(parameter, action, context);
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
        if (! LOG_ONLY) {
            throw access.accessControlException(permission, permission, protectionDomain.getCodeSource(), classLoader);
        }
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
        if (! LOG_ONLY) {
            throw access.accessControlException(permission, permission, protectionDomain.getCodeSource(), classLoader);
        }
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
        if (! LOG_ONLY) {
            throw access.accessControlException(permission, permission, protectionDomain.getCodeSource(), classLoader);
        }
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
        if (! LOG_ONLY) {
            throw access.accessControlException(permission, permission, protectionDomain.getCodeSource(), classLoader);
        }
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
        if (sm instanceof WildFlySecurityManager) {
            final Context ctx = CTX.get();
            if (! ctx.checking) {
                return getProperty(name, def);
            }
            ctx.checking = false;
            try {
                checkPropertyReadPermission(getCallerClass(1), name);
                return getProperty(name, def);
            } finally {
                ctx.checking = true;
            }
        } else if (sm != null) {
            AccessControlContext context = getCallerAccessControlContext();
            return doPrivileged(new ReadPropertyAction(name, def), context);
        }

        return getProperty(name, def);
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
        if (sm instanceof WildFlySecurityManager) {
            final Context ctx = CTX.get();
            if (! ctx.checking) {
                return def(getenv(name), def);
            }
            ctx.checking = false;
            try {
                checkEnvPropertyReadPermission(getCallerClass(1), name);
                return def(getenv(name), def);
            } finally {
                ctx.checking = true;
            }
        } else if (sm != null) {
            return doPrivileged(new ReadEnvironmentPropertyAction(name, def), getCallerAccessControlContext());
        }

        return getenv(name);
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
        if (sm instanceof WildFlySecurityManager) {
            final Context ctx = CTX.get();
            if (! ctx.checking) {
                return setProperty(name, value);
            }
            ctx.checking = false;
            try {
                checkPropertyWritePermission(getCallerClass(1), name);
                return setProperty(name, value);
            } finally {
                ctx.checking = true;
            }
        } else if (sm != null) {
            return doPrivileged(new WritePropertyAction(name, value), getCallerAccessControlContext());
        }

        return setProperty(name, value);
    }

    /**
     * Clear a property, doing a faster permission check that skips having to execute a privileged action frame.
     *
     * @param name the property name
     * @return the previous property value, or {@code null} if there was none
     */
    public static String clearPropertyPrivileged(String name) {
        final SecurityManager sm = getSecurityManager();
        if (sm instanceof WildFlySecurityManager) {
            final Context ctx = CTX.get();
            if (! ctx.checking) {
                return clearProperty(name);
            }
            ctx.checking = false;
            try {
                checkPropertyWritePermission(getCallerClass(1), name);
                return clearProperty(name);
            } finally {
                ctx.checking = true;
            }
        } else if (sm != null) {
            return doPrivileged(new ClearPropertyAction(name), getCallerAccessControlContext());
        }

        return clearProperty(name);
    }

    /**
     * Get the current thread's context class loader, doing a faster permission check that skips having to execute a
     * privileged action frame.
     *
     * @return the context class loader
     */
    public static ClassLoader getCurrentContextClassLoaderPrivileged() {
        final SecurityManager sm = System.getSecurityManager();
        if (sm instanceof WildFlySecurityManager) {
            final Context ctx = CTX.get();
            if (! ctx.checking) {
                return currentThread().getContextClassLoader();
            }
            ctx.checking = false;
            try {
                checkPDPermission(getCallerClass(1), GET_CLASS_LOADER_PERMISSION);
                return currentThread().getContextClassLoader();
            } finally {
                ctx.checking = true;
            }
        } else if (sm != null) {
            return doPrivileged(GetContextClassLoaderAction.getInstance(), getCallerAccessControlContext());
        }

        return currentThread().getContextClassLoader();
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
                checkPDPermission(getCallerClass(1), SET_CLASS_LOADER_PERMISSION);
                try {
                    return thread.getContextClassLoader();
                } finally {
                    thread.setContextClassLoader(newClassLoader);
                }
            } finally {
                ctx.checking = true;
            }
        } else if (sm != null) {
            return doPrivileged(new SetContextClassLoaderAction(newClassLoader), ACC_CACHE.get(getCallerClass(1)));
        }

        try {
            return thread.getContextClassLoader();
        } finally {
            thread.setContextClassLoader(newClassLoader);
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
                final Class<?> caller = getCallerClass(1);
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
        } else if (sm != null) {
            return doPrivileged(new SetContextClassLoaderAction(clazz.getClassLoader()), getCallerAccessControlContext());
        }

        try {
            return thread.getContextClassLoader();
        } finally {
            thread.setContextClassLoader(clazz.getClassLoader());
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
        if (sm instanceof WildFlySecurityManager) {
            final Context ctx = CTX.get();
            if (! ctx.checking) {
                return getProperties();
            }
            ctx.checking = false;
            try {
                checkPDPermission(getCallerClass(1), PROPERTIES_PERMISSION);
                return getProperties();
            } finally {
                ctx.checking = true;
            }
        } else if (sm != null) {
            return doPrivileged(GetSystemPropertiesAction.getInstance(), getCallerAccessControlContext());
        }

        return getProperties();
    }

    /**
     * Get the system environment map, doing a faster permission check that skips having to execute a privileged action
     * frame.
     *
     * @return the system environment map
     */
    public static Map<String, String> getSystemEnvironmentPrivileged() {
        final SecurityManager sm = System.getSecurityManager();
        if (sm instanceof WildFlySecurityManager) {
            final Context ctx = CTX.get();
            if (! ctx.checking) {
                return getenv();
            }
            ctx.checking = false;
            try {
                checkPDPermission(getCallerClass(1), ENVIRONMENT_PERMISSION);
                return getenv();
            } finally {
                ctx.checking = true;
            }
        } else if (sm != null) {
            return doPrivileged(GetEnvironmentAction.getInstance(), getCallerAccessControlContext());
        }

        return getenv();
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
        if (sm instanceof WildFlySecurityManager) {
            final Context ctx = CTX.get();
            if (! ctx.checking) {
                return clazz.getClassLoader();
            }
            ctx.checking = false;
            try {
                checkPDPermission(getCallerClass(1), GET_CLASS_LOADER_PERMISSION);
                return clazz.getClassLoader();
            } finally {
                ctx.checking = true;
            }
        } else if (sm != null) {
            return doPrivileged(new GetClassLoaderAction(clazz), getCallerAccessControlContext());
        }

        return clazz.getClassLoader();
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

    // Cannot be lambda due to JDK race conditions
    @SuppressWarnings("Convert2Lambda")
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

    // Cannot be lambda due to JDK race conditions
    @SuppressWarnings("Convert2Lambda")
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
        return (T) doPrivileged(PA_TRAMPOLINE1, ACC_CACHE.get(getCallerClass(1)));
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
        return (T) doPrivileged(PA_TRAMPOLINE2, ACC_CACHE.get(getCallerClass(1)));
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
            ProtectionDomain[] protectionDomainStack;
            if (accessControlContext == null || (protectionDomainStack = getProtectionDomainStack(accessControlContext)) == null || protectionDomainStack.length == 0) {
                combined = ACC_CACHE.get(getCallerClass(1));
            } else {
                final ProtectionDomain[] finalDomains = Arrays.copyOf(protectionDomainStack, protectionDomainStack.length + 1);
                finalDomains[protectionDomainStack.length] = getCallerClass(1).getProtectionDomain();
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
                combined = ACC_CACHE.get(getCallerClass(1));
            } else {
                final ProtectionDomain[] finalDomains = Arrays.copyOf(protectionDomainStack, protectionDomainStack.length + 1);
                finalDomains[protectionDomainStack.length] = getCallerClass(1).getProtectionDomain();
                combined = new AccessControlContext(finalDomains);
            }
        } finally {
            ctx.entered = false;
        }
        return (T) doPrivileged(PA_TRAMPOLINE2, combined);
    }

    private static AccessControlContext getCallerAccessControlContext() {
        final SecurityManager sm = getSecurityManager();
        final Context ctx = CTX.get();
        try {
            if (sm == null || sm instanceof WildFlySecurityManager) {
                return ACC_CACHE.get(getCallerClass(usingStackWalker ? 2 : 1));
            } else {
               final Class caller = getCallerClass(usingStackWalker ? 2 : 1);
               return doPrivileged( (PrivilegedAction<AccessControlContext>) () -> ACC_CACHE.get(caller));
            }
        } finally {
            ctx.entered = false;
        }
    }
}
