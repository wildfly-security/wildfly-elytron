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

package org.wildfly.security.auth.server.event;

import java.security.Principal;

import org.wildfly.security.authz.AuthorizationIdentity;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public abstract class RealmAuthorizationEvent extends RealmEvent {
    private final AuthorizationIdentity authorizationIdentity;
    private final Principal principal;

    /**
     * Construct a new instance.
     *
     * @param authorizationIdentity the authorization identity
     * @param principal the authorization principal
     */
    protected RealmAuthorizationEvent(final AuthorizationIdentity authorizationIdentity, final Principal principal) {
        this.authorizationIdentity = authorizationIdentity;
        this.principal = principal;
    }

    /**
     * Get the authorization identity of this event.
     *
     * @return the authorization identity of this event
     */
    public AuthorizationIdentity getAuthorizationIdentity() {
        return authorizationIdentity;
    }

    /**
     * Get the authorization principal.  This principal is the result of the application of the security domain's
     * principal rewriting policies and may not correspond to the name used to locate the identity in the realm.
     *
     * @return the authorization principal
     */
    public Principal getPrincipal() {
        return principal;
    }

    public <P, R> R accept(final RealmEventVisitor<P, R> visitor, final P param) {
        return visitor.handleAuthorizationEvent(this, param);
    }

    /**
     * Determine if this authorization was successful.
     *
     * @return {@code true} if the authentication was successful, {@code false} if it failed
     */
    public abstract boolean isAuthorized();
}
