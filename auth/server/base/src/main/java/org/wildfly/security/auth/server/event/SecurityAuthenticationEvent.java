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

import org.wildfly.security.auth.server.SecurityIdentity;

/**
 * A security authentication event.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public abstract class SecurityAuthenticationEvent extends SecurityDefiniteOutcomeEvent {

    /**
     * Create a new instance.
     *
     * @param securityIdentity the {@link SecurityIdentity} at the time of authentication.
     * @param successful was the authentication process successful.
     */
    SecurityAuthenticationEvent(SecurityIdentity securityIdentity, boolean successful) {
        super(securityIdentity, successful);
    }

    @Override
    public <P, R> R accept(SecurityEventVisitor<P, R> visitor, P param) {
        return visitor.handleAuthenticationEvent(this, param);
    }

}
