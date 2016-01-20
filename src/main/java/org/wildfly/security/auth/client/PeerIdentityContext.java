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

import java.util.function.Function;

import org.wildfly.security.auth.AuthenticationException;
import org.wildfly.security.auth.ReauthenticationException;

/**
 * A peer identity context.  The peer identity is relevant only to this context.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public abstract class PeerIdentityContext {
    private final ThreadLocal<PeerIdentity> currentIdentity;

    /**
     * Construct a new instance.
     */
    protected PeerIdentityContext() {
        currentIdentity = new ThreadLocal<>();
    }

    /**
     * Get the currently set peer identity for this context.
     *
     * @return the currently set peer identity for this context, or {@code null} if no identity is set
     */
    public final PeerIdentity getCurrentIdentity() {
        return currentIdentity.get();
    }

    /**
     * Authenticate a new peer identity.  The authentication operation may be deferred if the backend cannot perform
     * authentications on demand.  If so, and the authentication fails, a {@link ReauthenticationException} may be
     * thrown at a later time.
     *
     * @param authenticationConfiguration the authentication configuration to use
     * @return the peer identity
     * @throws AuthenticationException if an immediate authentication error occurs
     */
    public abstract PeerIdentity authenticate(AuthenticationConfiguration authenticationConfiguration) throws AuthenticationException;

    /**
     * Construct a new peer identity.  The given function uses the opaque one-time configuration object to construct the
     * identity, which must be passed as-is to the constructor of the {@link PeerIdentity} class.  This object must not be
     * retained or made available after the identity is constructed; such misuse may result in an exception or undefined
     * behavior.
     *
     * @param constructFunction a function that, when applied, constructs a new peer identity
     * @return the constructed peer identity
     */
    protected final <I> I constructIdentity(Function<PeerIdentity.Configuration, I> constructFunction) {
        final PeerIdentity.Configuration conf = new PeerIdentity.Configuration(this);
        try {
            return constructFunction.apply(conf);
        } finally {
            conf.terminate();
        }
    }

    /**
     * Determine whether this context owns the given identity.
     *
     * @param identity the identity
     * @return {@code true} if this context owns the identity, {@code false} otherwise
     */
    public final boolean owns(PeerIdentity identity) {
        return identity != null && identity.getPeerIdentityContext() == this;
    }

    final PeerIdentity getAndSetPeerIdentity(PeerIdentity newIdentity) {
        assert newIdentity == null || newIdentity.getPeerIdentityContext() == this;
        try {
            return currentIdentity.get();
        } finally {
            if (newIdentity == null) {
                currentIdentity.remove();
            } else {
                currentIdentity.set(newIdentity);
            }
        }
    }

    void setPeerIdentity(PeerIdentity newIdentity) {
        assert newIdentity == null || newIdentity.getPeerIdentityContext() == this;
        if (newIdentity == null) {
            currentIdentity.remove();
        } else {
            currentIdentity.set(newIdentity);
        }
    }
}
