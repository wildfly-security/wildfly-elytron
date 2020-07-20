/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2015 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.auth.client;

import java.security.Principal;
import java.security.PrivilegedAction;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Collections;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.function.BiConsumer;
import java.util.function.BiFunction;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.ObjIntConsumer;
import java.util.function.Supplier;

import org.wildfly.common.Assert;
import org.wildfly.security.ParametricPrivilegedAction;
import org.wildfly.security.ParametricPrivilegedExceptionAction;
import org.wildfly.security.auth.client._private.ElytronMessages;
import org.wildfly.security.authz.Attributes;

/**
 * A peer's authenticated identity.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public abstract class PeerIdentity {
    private final PeerIdentityContext context;
    private final Principal peerPrincipal;

    /**
     * Construct a new instance.
     *
     * @param configuration the opaque configuration (must not be {@code null})
     * @param peerPrincipal the peer principal (must not be {@code null})
     */
    protected PeerIdentity(final Configuration configuration, final Principal peerPrincipal) {
        Assert.checkNotNullParam("configuration", configuration);
        Assert.checkNotNullParam("peerPrincipal", peerPrincipal);
        context = configuration.getContext();
        this.peerPrincipal = peerPrincipal;
    }

    /**
     * Perform an optional pre-association action, called before association with the current thread.
     */
    protected void preAssociate() {}

    /**
     * Perform an optional post-association action, called after association with the current thread has completed.
     */
    protected void postAssociate() {}

    private void safePostAssociate() {
        try {
            postAssociate();
        } catch (Throwable t) {
            ElytronMessages.log.postAssociationFailed(t);
        }
    }

    /**
     * Determine if the peer identity context of this identity is the same as that of the given identity.
     *
     * @param other the other peer identity
     * @return {@code true} if the identities share a context, {@code false} otherwise
     */
    public boolean isSamePeerIdentityContext(PeerIdentity other) {
        return other != null && context == other.context;
    }

    /**
     * Run an action under this identity.
     *
     * @param runnable the action to run
     */
    public void runAs(Runnable runnable) {
        PeerIdentity old = context.getAndSetPeerIdentity(this);
        try {
            preAssociate();
            try {
                runnable.run();
            } finally {
                safePostAssociate();
            }
        } finally {
            context.setPeerIdentity(old);
        }
    }

    /**
     * Run an action under this identity.
     *
     * @param callable the action to run
     * @param <T> the action return type
     * @return the action result (may be {@code null})
     * @throws PrivilegedActionException if the action fails
     */
    public <T> T runAs(Callable<T> callable) throws Exception {
        PeerIdentity old = context.getAndSetPeerIdentity(this);
        try {
            preAssociate();
            try {
                return callable.call();
            } finally {
                safePostAssociate();
            }
        } finally {
            context.setPeerIdentity(old);
        }
    }

    /**
     * Run an action under this identity.
     *
     * @param action the action to run
     * @param <T> the action return type
     * @return the action result (may be {@code null})
     */
    public <T> T runAs(PrivilegedAction<T> action) {
        PeerIdentity old = context.getAndSetPeerIdentity(this);
        try {
            preAssociate();
            try {
                return action.run();
            } finally {
                safePostAssociate();
            }
        } finally {
            context.setPeerIdentity(old);
        }
    }

    /**
     * Run an action under this identity.
     *
     * @param action the action to run
     * @param <T> the action return type
     * @return the action result (may be {@code null})
     * @throws PrivilegedActionException if the action fails
     */
    public <T> T runAs(PrivilegedExceptionAction<T> action) throws PrivilegedActionException {
        PeerIdentity old = context.getAndSetPeerIdentity(this);
        try {
            preAssociate();
            try {
                return action.run();
            } finally {
                safePostAssociate();
            }
        } catch (RuntimeException | PrivilegedActionException e) {
            throw e;
        } catch (Exception e) {
            throw new PrivilegedActionException(e);
        } finally {
            context.setPeerIdentity(old);
        }
    }

    /**
     * Run an action under this identity.
     *
     * @param parameter the parameter to pass to the action
     * @param action the action to run
     * @param <T> the action return type
     * @param <P> the action parameter type
     * @return the action result (may be {@code null})
     */
    public <T, P> T runAs(P parameter, ParametricPrivilegedAction<T, P> action) {
        PeerIdentity old = context.getAndSetPeerIdentity(this);
        try {
            preAssociate();
            try {
                return action.run(parameter);
            } finally {
                safePostAssociate();
            }
        } finally {
            context.setPeerIdentity(old);
        }
    }

    /**
     * Run an action under this identity.
     *
     * @param parameter the parameter to pass to the action
     * @param action the action to run
     * @param <T> the action return type
     * @param <P> the action parameter type
     * @return the action result (may be {@code null})
     * @throws PrivilegedActionException if the action fails
     */
    public <T, P> T runAs(P parameter, ParametricPrivilegedExceptionAction<T, P> action) throws PrivilegedActionException {
        PeerIdentity old = context.getAndSetPeerIdentity(this);
        try {
            preAssociate();
            try {
                return action.run(parameter);
            } finally {
                safePostAssociate();
            }
        } catch (RuntimeException | PrivilegedActionException e) {
            throw e;
        } catch (Exception e) {
            throw new PrivilegedActionException(e);
        } finally {
            context.setPeerIdentity(old);
        }
    }

    /**
     * Run an action under this identity.
     *
     * @param parameter the parameter to pass to the action
     * @param action the action to run
     * @param <T> the action parameter type
     * @param <R> the action return type
     * @return the action result (may be {@code null})
     */
    public <T, R> R runAsFunction(T parameter, Function<T, R> action) {
        PeerIdentity old = context.getAndSetPeerIdentity(this);
        try {
            preAssociate();
            try {
                return action.apply(parameter);
            } finally {
                safePostAssociate();
            }
        } finally {
            context.setPeerIdentity(old);
        }
    }

    /**
     * Run an action under this identity.
     *
     * @param parameter1 the first parameter to pass to the action
     * @param parameter2 the second parameter to pass to the action
     * @param action the action to run
     * @param <T> the action first parameter type
     * @param <U> the action second parameter type
     * @param <R> the action return type
     * @return the action result (may be {@code null})
     */
    public <T, U, R> R runAsFunction(T parameter1, U parameter2, BiFunction<T, U, R> action) {
        PeerIdentity old = context.getAndSetPeerIdentity(this);
        try {
            preAssociate();
            try {
                return action.apply(parameter1, parameter2);
            } finally {
                safePostAssociate();
            }
        } finally {
            context.setPeerIdentity(old);
        }
    }

    /**
     * Run an action under this identity.
     *
     * @param parameter the parameter to pass to the action
     * @param action the action to run
     * @param <T> the action parameter type
     */
    public <T> void runAsConsumer(T parameter, Consumer<T> action) {
        PeerIdentity old = context.getAndSetPeerIdentity(this);
        try {
            preAssociate();
            try {
                action.accept(parameter);
            } finally {
                safePostAssociate();
            }
        } finally {
            context.setPeerIdentity(old);
        }
    }

    /**
     * Run an action under this identity.
     *
     * @param parameter1 the first parameter to pass to the action
     * @param parameter2 the second parameter to pass to the action
     * @param action the action to run
     * @param <T> the action first parameter type
     * @param <U> the action second parameter type
     */
    public <T, U> void runAsConsumer(T parameter1, U parameter2, BiConsumer<T, U> action) {
        PeerIdentity old = context.getAndSetPeerIdentity(this);
        try {
            preAssociate();
            try {
                action.accept(parameter1, parameter2);
            } finally {
                safePostAssociate();
            }
        } finally {
            context.setPeerIdentity(old);
        }
    }

    /**
     * Run an action under this identity.
     *
     * @param supplier the action to run
     * @param <T> the action return type
     * @return the action result (may be {@code null})
     * @throws PrivilegedActionException if the action fails
     */
    public <T> T runAsSupplier(Supplier<T> supplier) throws Exception {
        PeerIdentity old = context.getAndSetPeerIdentity(this);
        try {
            preAssociate();
            try {
                return supplier.get();
            } finally {
                safePostAssociate();
            }
        } finally {
            context.setPeerIdentity(old);
        }
    }

    /**
     * Run an action under a series of identities.
     *
     * @param runnable the action to run
     * @param identities the identities to use
     */
    public static void runAsAll(Runnable runnable, PeerIdentity... identities) {
        int length = identities.length;
        for (int i = 0; i < length; i ++) {
            PeerIdentity identity = identities[i];
            boolean ok = false;
            try {
                identity.preAssociate();
                ok = true;
            } finally {
                if (! ok) {
                    for (--i; i >= 0; --i) {
                        identities[i].safePostAssociate();
                    }
                }
            }
        }
        try {
            runnable.run();
        } finally {
            for (int i = length - 1; i >= 0; i--) {
                identities[i].safePostAssociate();
            }
        }
    }

    /**
     * Run an action under a series of identities.
     *
     * @param callable the action to run
     * @param identities the identities to use
     * @param <T> the action return type
     */
    public static <T> T runAsAll(Callable<T> callable, PeerIdentity... identities) throws Exception {
        int length = identities.length;
        for (int i = 0; i < length; i ++) {
            PeerIdentity identity = identities[i];
            boolean ok = false;
            try {
                identity.preAssociate();
                ok = true;
            } finally {
                if (! ok) {
                    for (--i; i >= 0; --i) {
                        identities[i].safePostAssociate();
                    }
                }
            }
        }
        try {
            return callable.call();
        } finally {
            for (int i = length - 1; i >= 0; i--) {
                identities[i].safePostAssociate();
            }
        }
    }

    /**
     * Run an action under a series of identities.
     *
     * @param privilegedAction the action to run
     * @param identities the identities to use
     * @param <T> the action return type
     */
    public static <T> T runAsAll(PrivilegedAction<T> privilegedAction, PeerIdentity... identities) {
        int length = identities.length;
        for (int i = 0; i < length; i ++) {
            PeerIdentity identity = identities[i];
            boolean ok = false;
            try {
                identity.preAssociate();
                ok = true;
            } finally {
                if (! ok) {
                    for (--i; i >= 0; --i) {
                        identities[i].safePostAssociate();
                    }
                }
            }
        }
        try {
            return privilegedAction.run();
        } finally {
            for (int i = length - 1; i >= 0; i--) {
                identities[i].safePostAssociate();
            }
        }
    }

    /**
     * Run an action under a series of identities.
     *
     * @param privilegedAction the action to run
     * @param identities the identities to use
     * @param <T> the action return type
     * @throws PrivilegedActionException if the action throws an exception
     */
    public static <T> T runAsAll(PrivilegedExceptionAction<T> privilegedAction, PeerIdentity... identities) throws PrivilegedActionException {
        int length = identities.length;
        for (int i = 0; i < length; i ++) {
            PeerIdentity identity = identities[i];
            boolean ok = false;
            try {
                identity.preAssociate();
                ok = true;
            } finally {
                if (! ok) {
                    for (--i; i >= 0; --i) {
                        identities[i].safePostAssociate();
                    }
                }
            }
        }
        try {
            return privilegedAction.run();
        } catch (RuntimeException | PrivilegedActionException e) {
            throw e;
        } catch (Exception e) {
            throw new PrivilegedActionException(e);
        } finally {
            for (int i = length - 1; i >= 0; i--) {
                identities[i].safePostAssociate();
            }
        }
    }

    /**
     * Run an action under a series of identities.
     *
     * @param parameter the parameter to pass to the action
     * @param privilegedAction the action to run
     * @param identities the identities to use
     * @param <T> the action return type
     * @param <P> the action parameter type
     */
    public static <T, P> T runAsAll(P parameter, ParametricPrivilegedAction<T, P> privilegedAction, PeerIdentity... identities) {
        int length = identities.length;
        for (int i = 0; i < length; i ++) {
            PeerIdentity identity = identities[i];
            boolean ok = false;
            try {
                identity.preAssociate();
                ok = true;
            } finally {
                if (! ok) {
                    for (--i; i >= 0; --i) {
                        identities[i].safePostAssociate();
                    }
                }
            }
        }
        try {
            return privilegedAction.run(parameter);
        } finally {
            for (int i = length - 1; i >= 0; i--) {
                identities[i].safePostAssociate();
            }
        }
    }

    /**
     * Run an action under a series of identities.
     *
     * @param parameter the parameter to pass to the action
     * @param privilegedAction the action to run
     * @param identities the identities to use
     * @param <T> the action return type
     * @param <P> the action parameter type
     * @throws PrivilegedActionException if the action throws an exception
     */
    public static <T, P> T runAsAll(P parameter, ParametricPrivilegedExceptionAction<T, P> privilegedAction, PeerIdentity... identities) throws PrivilegedActionException {
        int length = identities.length;
        for (int i = 0; i < length; i ++) {
            PeerIdentity identity = identities[i];
            boolean ok = false;
            try {
                identity.preAssociate();
                ok = true;
            } finally {
                if (! ok) {
                    for (--i; i >= 0; --i) {
                        identities[i].safePostAssociate();
                    }
                }
            }
        }
        try {
            return privilegedAction.run(parameter);
        } catch (RuntimeException | PrivilegedActionException e) {
            throw e;
        } catch (Exception e) {
            throw new PrivilegedActionException(e);
        } finally {
            for (int i = length - 1; i >= 0; i--) {
                identities[i].safePostAssociate();
            }
        }
    }

    /**
     * Run an action under a series of identities.
     *
     * @param parameter the parameter to pass to the action
     * @param privilegedAction the action to run
     * @param identities the identities to use
     * @param <R> the action return type
     * @param <T> the action parameter type
     */
    public static <R, T> R runAsAllFunction(T parameter, Function<T, R> privilegedAction, PeerIdentity... identities) {
        return runAsAllFunction(privilegedAction, parameter, Function::apply, identities);
    }

    /**
     * Run an action under a series of identities.
     *
     * @param parameter1 the first parameter to pass to the action
     * @param parameter2 the second parameter to pass to the action
     * @param privilegedAction the action to run
     * @param identities the identities to use
     * @param <T> the action first parameter type
     * @param <U> the action second parameter type
     * @param <R> the action return type
     */
    public static <T, U, R> R runAsAllFunction(T parameter1, U parameter2, BiFunction<T, U, R> privilegedAction, PeerIdentity... identities) {
        int length = identities.length;
        for (int i = 0; i < length; i ++) {
            PeerIdentity identity = identities[i];
            boolean ok = false;
            try {
                identity.preAssociate();
                ok = true;
            } finally {
                if (! ok) {
                    for (--i; i >= 0; --i) {
                        identities[i].safePostAssociate();
                    }
                }
            }
        }
        try {
            return privilegedAction.apply(parameter1, parameter2);
        } finally {
            for (int i = length - 1; i >= 0; i--) {
                identities[i].safePostAssociate();
            }
        }
    }

    /**
     * Run an action under a series of identities.
     *
     * @param parameter the parameter to pass to the action
     * @param privilegedAction the action to run
     * @param identities the identities to use
     * @param <T> the action parameter type
     */
    public static <T> void runAsAllConsumer(T parameter, Consumer<T> privilegedAction, PeerIdentity... identities) {
        runAsAllConsumer(privilegedAction, parameter, Consumer::accept, identities);
    }

    /**
     * Run an action under a series of identities.
     *
     * @param parameter1 the first parameter to pass to the action
     * @param parameter2 the second parameter to pass to the action
     * @param privilegedAction the action to run
     * @param identities the identities to use
     * @param <T> the action first parameter type
     * @param <U> the action second parameter type
     */
    public static <T, U> void runAsAllConsumer(T parameter1, U parameter2, BiConsumer<T, U> privilegedAction, PeerIdentity... identities) {
        int length = identities.length;
        for (int i = 0; i < length; i ++) {
            PeerIdentity identity = identities[i];
            boolean ok = false;
            try {
                identity.preAssociate();
                ok = true;
            } finally {
                if (! ok) {
                    for (--i; i >= 0; --i) {
                        identities[i].safePostAssociate();
                    }
                }
            }
        }
        try {
            privilegedAction.accept(parameter1, parameter2);
        } finally {
            for (int i = length - 1; i >= 0; i--) {
                identities[i].safePostAssociate();
            }
        }
    }

    /**
     * Run an action under a series of identities.
     *
     * @param parameter1 the first parameter to pass to the action
     * @param parameter2 the second parameter to pass to the action
     * @param privilegedAction the action to run
     * @param identities the identities to use
     * @param <T> the action first parameter type
     */
    public static <T> void runAsAllObjIntConsumer(T parameter1, int parameter2, ObjIntConsumer<T> privilegedAction, PeerIdentity... identities) {
        int length = identities.length;
        for (int i = 0; i < length; i ++) {
            PeerIdentity identity = identities[i];
            boolean ok = false;
            try {
                identity.preAssociate();
                ok = true;
            } finally {
                if (! ok) {
                    for (--i; i >= 0; --i) {
                        identities[i].safePostAssociate();
                    }
                }
            }
        }
        try {
            privilegedAction.accept(parameter1, parameter2);
        } finally {
            for (int i = length - 1; i >= 0; i--) {
                identities[i].safePostAssociate();
            }
        }
    }

    /**
     * Run an action under a series of identities.
     *
     * @param action the action to run
     * @param identities the identities to use
     * @param <T> the action return type
     */
    public static <T> T runAsAllSupplier(Supplier<T> action, PeerIdentity... identities) {
        int length = identities.length;
        for (int i = 0; i < length; i ++) {
            PeerIdentity identity = identities[i];
            boolean ok = false;
            try {
                identity.preAssociate();
                ok = true;
            } finally {
                if (! ok) {
                    for (--i; i >= 0; --i) {
                        identities[i].safePostAssociate();
                    }
                }
            }
        }
        try {
            return action.get();
        } finally {
            for (int i = length - 1; i >= 0; i--) {
                identities[i].safePostAssociate();
            }
        }
    }

    /**
     * Get the peer principal.
     *
     * @return the peer principal (not {@code null})
     */
    public Principal getPeerPrincipal() {
        return peerPrincipal;
    }

    /**
     * Get the peer identity roles.  The default implementation returns an empty set.
     *
     * @return the peer identity role set (not {@code null})
     */
    public Set<String> getPeerRoles() {
        return Collections.emptySet();
    }

    /**
     * Determine whether the peer identity has a given role name.  The default implementation returns {@code false}.
     *
     * @param roleName the role name
     * @return {@code true} if the peer identity has the role, {@code false} otherwise
     */
    public boolean hasPeerRole(final String roleName) {
        return false;
    }

    /**
     * Get the attribute set for the peer identity.  The default implementation returns an empty attributes set.
     *
     * @return the peer identity attributes
     */
    public Attributes getPeerAttributes() {
        return Attributes.EMPTY;
    }

    /**
     * Get a specific attribute value for the peer identity.  The default implementation returns {@code null}.
     *
     * @param key the attribute name
     * @return the attribute value entry, or {@code null} if there is no matching entry
     */
    public Attributes.Entry getPeerAttribute(final String key) {
        return null;
    }

    /**
     * Get the peer identity context for this identity.
     *
     * @return the peer identity context for this identity (not {@code null})
     */
    protected final PeerIdentityContext getPeerIdentityContext() {
        return context;
    }

    /**
     * The opaque configuration to apply to a peer identity.
     */
    public static final class Configuration {
        private final PeerIdentityContext context;
        private final Thread thread = Thread.currentThread();
        private boolean terminated;

        Configuration(final PeerIdentityContext context) {
            this.context = context;
        }

        PeerIdentityContext getContext() {
            if (thread != Thread.currentThread() || terminated) {
                throw new SecurityException();
            }
            return context;
        }

        void terminate() {
            terminated = true;
        }
    }
}
