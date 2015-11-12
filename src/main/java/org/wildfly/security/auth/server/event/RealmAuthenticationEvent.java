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

import org.wildfly.security.auth.server.RealmIdentity;

/**
 * A realm authentication event.  The realm identity may be destroyed at some point after the event is handled.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public abstract class RealmAuthenticationEvent extends RealmEvent {

    private final RealmIdentity realmIdentity;

    /**
     * Construct a new instance.
     *
     * @param realmIdentity the realm identity of the authentication event
     */
    protected RealmAuthenticationEvent(final RealmIdentity realmIdentity) {
        this.realmIdentity = realmIdentity;
    }

    /**
     * Get the realm identity.
     *
     * @return the realm identity
     */
    public final RealmIdentity getRealmIdentity() {
        return realmIdentity;
    }

    public <P, R> R accept(final RealmEventVisitor<P, R> visitor, final P param) {
        return visitor.handleAuthenticationEvent(this, param);
    }

    /**
     * Determine if this authentication was definitely successful.
     *
     * @return {@code true} if the authentication was definitely successful, {@code false} if it was not definitely
     *      successful
     */
    public abstract boolean isSuccess();

    /**
     * Determine if this authentication definitely failed.
     *
     * @return {@code true} if the authentication definitely failed, {@code false} if it did not definitely
     *      fail
     */
    public abstract boolean isFailure();
}
