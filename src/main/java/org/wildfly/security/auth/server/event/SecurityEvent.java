/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2017 Red Hat, Inc., and individual contributors
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

import static org.wildfly.common.Assert.checkNotNullParam;

import java.time.Instant;

import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.auth.server.SecurityIdentity;

/**
 * Base class for security events emitted from a {@link SecurityDomain}.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public abstract class SecurityEvent {

    private final Instant instant = Instant.now();

    private final SecurityIdentity securityIdentity;

    /**
     * Constructor for a new instance.
     *
     * @param securityIdentity the current {@link SecurityIdentity} for the event.
     */
    SecurityEvent(SecurityIdentity securityIdentity) {
        this.securityIdentity = checkNotNullParam("securityIdentity", securityIdentity);
    }

    /**
     * Get the {@link SecurityIdentity} that was active at the time this event was triggered.
     *
     * @return the {@link SecurityIdentity} that was active at the time this event was triggered.
     */
    public SecurityIdentity getSecurityIdentity() {
        return securityIdentity;
    }

    /**
     * Obtain the {@link Instant} this event was created.
     *
     * @return the {@link Instant} this event was created.
     */
    public Instant getInstant() {
        return instant;
    }

    /**
     * Accept the given visitor, calling the method which is most applicable to this event type.
     *
     * @param visitor the visitor
     * @param param the parameter to pass to the visitor {@code handleXxx} method
     * @param <P> the visitor parameter type
     * @param <R> the visitor return type
     * @return the value returned from the visitor {@code handleXxx} method
     */
    public <P, R> R accept(SecurityEventVisitor<P, R> visitor, P param) {
        return visitor.handleUnknownEvent(this, param);
    }

}
