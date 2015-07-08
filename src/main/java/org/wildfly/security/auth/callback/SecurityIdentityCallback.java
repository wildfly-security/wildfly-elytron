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

package org.wildfly.security.auth.callback;

import java.io.Serializable;

import org.wildfly.security.auth.server.SecurityIdentity;

/**
 * A server-side callback used to pass a realm identity from the callback handler to the authentication mechanism.  If
 * no realm identity is returned, any inflowed security context will be treated as anonymous.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class SecurityIdentityCallback implements ExtendedCallback, Serializable {

    private static final long serialVersionUID = -238599667659078631L;

    /**
     * @serial The security identity.
     */
    private SecurityIdentity securityIdentity;

    /**
     * Construct a new instance.
     */
    public SecurityIdentityCallback() {
    }

    /**
     * Get the realm identity.
     *
     * @return the realm identity, or {@code null} if there is none
     */
    public SecurityIdentity getSecurityIdentity() {
        return securityIdentity;
    }

    /**
     * Set the realm identity.
     *
     * @param securityIdentity the realm identity, or {@code null} if there is none
     */
    public void setSecurityIdentity(final SecurityIdentity securityIdentity) {
        this.securityIdentity = securityIdentity;
    }
}
