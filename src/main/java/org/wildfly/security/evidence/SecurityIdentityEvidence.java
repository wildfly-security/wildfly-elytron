/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.evidence;

import java.security.Principal;

import org.wildfly.common.Assert;
import org.wildfly.security.auth.server.SecurityIdentity;

/**
 * A piece of evidence that is comprised of a security identity.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public final class SecurityIdentityEvidence implements Evidence {

    private final SecurityIdentity securityIdentity;

    /**
     * Construct a new instance.
     *
     * @param securityIdentity the security identity to use (must not be {@code null})
     */
    public SecurityIdentityEvidence(final SecurityIdentity securityIdentity) {
        Assert.checkNotNullParam("securityIdentity", securityIdentity);
        this.securityIdentity = securityIdentity;
    }

    /**
     * Get the security identity.
     *
     * @return the security identity (not {@code null})
     */
    public SecurityIdentity getSecurityIdentity() {
        return securityIdentity;
    }

    @Override
    public Principal getPrincipal() {
        return getSecurityIdentity().getPrincipal();
    }
}
