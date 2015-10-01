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
import java.util.Set;
import java.util.concurrent.Callable;

import org.wildfly.security.ParametricPrivilegedAction;
import org.wildfly.security.ParametricPrivilegedExceptionAction;
import org.wildfly.security.authz.Attributes;

/**
 * A peer's authenticated identity.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class PeerIdentity {
    private final PeerIdentityContext context;
    private final Principal peerPrincipal;
    private final PeerIdentityHandle handle;

    PeerIdentity(final PeerIdentityContext context, final Principal peerPrincipal, final PeerIdentityHandle handle) {
        this.context = context;
        this.peerPrincipal = peerPrincipal;
        this.handle = handle;
    }

    /**
     * Run an action under this identity.
     *
     * @param runnable the action to run
     */
    public void runAs(Runnable runnable) {
        PeerIdentity old = context.getAndSetPeerIdentity(this);
        try {
            runnable.run();
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
            return callable.call();
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
            return action.run();
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
            try {
                return action.run();
            } catch (Exception e) {
                throw new PrivilegedActionException(e);
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
     */
    public <T, P> T runAs(P parameter, ParametricPrivilegedAction<T, P> action) {
        PeerIdentity old = context.getAndSetPeerIdentity(this);
        try {
            return action.run(parameter);
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
            try {
                return action.run(parameter);
            } catch (Exception e) {
                throw new PrivilegedActionException(e);
            }
        } finally {
            context.setPeerIdentity(old);
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
     * Get the peer identity roles.
     *
     * @return the peer identity role set
     */
    public Set<String> getPeerRoles() {
        return handle.getPeerRoles();
    }

    /**
     * Determine whether the peer identity has a given role name.
     *
     * @param roleName the role name
     * @return {@code true} if the peer identity has the role, {@code false} otherwise
     */
    public boolean hasPeerRole(final String roleName) {
        return handle.hasPeerRole(roleName);
    }

    /**
     * Get the attribute set for the peer identity.
     *
     * @return the peer identity attributes
     */
    public Attributes getPeerAttributes() {
        return handle.getPeerAttributes();
    }

    /**
     * Get a specific attribute value for the peer identity.
     *
     * @param key the attribute name
     * @return the attribute value entry, or {@code null} if there is no matching entry
     */
    public Attributes.Entry getPeerAttribute(final String key) {
        return handle.getPeerAttribute(key);
    }

    PeerIdentityContext getContext() {
        return context;
    }
}
