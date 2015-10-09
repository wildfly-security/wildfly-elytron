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

import org.wildfly.security.auth.AuthenticationException;
import org.wildfly.security.auth.ReauthenticationException;
import org.wildfly.security.auth.principal.AnonymousPrincipal;

/**
 * A peer identity context.  The peer identity is relevant only to this context.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class PeerIdentityContext {
    private final PeerIdentity anonymous;
    private final ThreadLocal<PeerIdentity> currentIdentity;
    private final PeerIdentityProvider peerIdentityProvider;

    PeerIdentityContext(final PeerIdentityHandle anonymousHandle, final PeerIdentityProvider peerIdentityProvider) {
        this.peerIdentityProvider = peerIdentityProvider;
        anonymous = new PeerIdentity(this, AnonymousPrincipal.getInstance(), anonymousHandle);
        currentIdentity = new ThreadLocal<>();
    }

    /**
     * Get the anonymous peer identity for this context.
     *
     * @return the anonymous peer identity for this context
     */
    public PeerIdentity getAnonymousPeerIdentity() {
        return anonymous;
    }

    /**
     * Get the currently set peer identity for this context.
     *
     * @return the currently set peer identity for this context
     */
    public PeerIdentity getCurrentIdentity() {
        final PeerIdentity identity = currentIdentity.get();
        return identity == null ? anonymous : identity;
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
    public PeerIdentity authenticate(AuthenticationConfiguration authenticationConfiguration) throws AuthenticationException {
        final PeerIdentityHandle handle = peerIdentityProvider.authenticate(authenticationConfiguration);
        return new PeerIdentity(this, authenticationConfiguration.getPrincipal(), handle);
    }

    PeerIdentity getAndSetPeerIdentity(PeerIdentity newIdentity) {
        assert newIdentity.getContext() == this;
        try {
            return currentIdentity.get();
        } finally {
            if (newIdentity == anonymous) {
                currentIdentity.remove();
            } else {
                currentIdentity.set(newIdentity);
            }
        }
    }

    void setPeerIdentity(PeerIdentity newIdentity) {
        assert newIdentity.getContext() == this;
        if (newIdentity == anonymous) {
            currentIdentity.remove();
        } else {
            currentIdentity.set(newIdentity);
        }
    }
}
