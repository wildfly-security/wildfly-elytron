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
 * An event indicating that authentication was abandoned before it could complete.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class RealmAbandonedAuthenticationEvent extends RealmAuthenticationEvent {
    /**
     * Construct a new instance.
     *
     * @param realmIdentity the realm identity of the authentication event
     */
    public RealmAbandonedAuthenticationEvent(final RealmIdentity realmIdentity) {
        super(realmIdentity);
    }

    public <P, R> R accept(final RealmEventVisitor<P, R> visitor, final P param) {
        return visitor.handleAbandonedAuthenticationEvent(this, param);
    }

    public boolean isSuccess() {
        return false;
    }

    public boolean isFailure() {
        return false;
    }
}
