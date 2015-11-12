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

/**
 * A class which provides an easy way to handle realm events based on the type of the event.  The visitor can accept
 * a parameter and return a value.  To invoke the appropriate visitor method based on the event type, use the
 * {@link RealmEvent#accept(RealmEventVisitor, Object) &lt;P,&nbsp;R&gt;&nbsp;R&nbsp;RealmEvent.accept(RealmEventVisitor&lt;P,&nbsp;R&gt;,&nbsp;P)} method.
 *
 * @param <P> the visitor's parameter type (may be {@link Void})
 * @param <R> the visitor's return type (may be {@link Void})
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public abstract class RealmEventVisitor<P, R> {
    /**
     * Construct a new instance.
     */
    protected RealmEventVisitor() {
    }

    /**
     * Handle any unhandled realm event.
     *
     * @param event the realm event
     * @param param the visitor parameter
     * @return the visitor return value
     */
    public R handleUnknownEvent(final RealmEvent event, final P param) {
        return null;
    }

    /**
     * Handle any authentication-related realm event.
     *
     * @param event the realm event
     * @param param the visitor parameter
     * @return the visitor return value
     */
    public R handleAuthenticationEvent(final RealmAuthenticationEvent event, final P param) {
        return handleUnknownEvent(event, param);
    }

    /**
     * Handle an abandoned authentication realm event.
     *
     * @param event the realm event
     * @param param the visitor parameter
     * @return the visitor return value
     */
    public R handleAbandonedAuthenticationEvent(final RealmAbandonedAuthenticationEvent event, final P param) {
        return handleAuthenticationEvent(event, param);
    }

    /**
     * Handle a definite-outcome authentication realm event.
     *
     * @param event the realm event
     * @param param the visitor parameter
     * @return the visitor return value
     */
    public R handleDefiniteOutcomeAuthenticationEvent(final RealmDefiniteOutcomeAuthenticationEvent event, final P param) {
        return handleAuthenticationEvent(event, param);
    }

    /**
     * Handle a successful authentication realm event.
     *
     * @param event the realm event
     * @param param the visitor parameter
     * @return the visitor return value
     */
    public R handleSuccessfulAuthenticationEvent(final RealmSuccessfulAuthenticationEvent event, final P param) {
        return handleDefiniteOutcomeAuthenticationEvent(event, param);
    }

    /**
     * Handle a failed authentication realm event.
     *
     * @param event the realm event
     * @param param the visitor parameter
     * @return the visitor return value
     */
    public R handleFailedAuthenticationEvent(final RealmFailedAuthenticationEvent event, final P param) {
        return handleDefiniteOutcomeAuthenticationEvent(event, param);
    }

    /**
     * Handle any authorization-related realm event.
     *
     * @param event the realm event
     * @param param the visitor parameter
     * @return the visitor return value
     */
    public R handleAuthorizationEvent(final RealmAuthorizationEvent event, final P param) {
        return handleUnknownEvent(event, param);
    }

    /**
     * Handle an identity authorization realm event.
     *
     * @param event the realm event
     * @param param the visitor parameter
     * @return the visitor return value
     */
    public R handleIdentityAuthorizationEvent(final RealmIdentityAuthorizationEvent event, final P param) {
        return handleAuthorizationEvent(event, param);
    }

    /**
     * Handle an identity successful authorization realm event.
     *
     * @param event the realm event
     * @param param the visitor parameter
     * @return the visitor return value
     */
    public R handleIdentitySuccessfulAuthorizationEvent(final RealmIdentitySuccessfulAuthorizationEvent event, final P param) {
        return handleIdentityAuthorizationEvent(event, param);
    }

    /**
     * Handle an identity failed authorization realm event.
     *
     * @param event the realm event
     * @param param the visitor parameter
     * @return the visitor return value
     */
    public R handleIdentityFailedAuthorizationEvent(final RealmIdentityFailedAuthorizationEvent event, final P param) {
        return handleIdentityAuthorizationEvent(event, param);
    }
}
