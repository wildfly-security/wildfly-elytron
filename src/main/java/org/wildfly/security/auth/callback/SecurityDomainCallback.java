/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2014 Red Hat, Inc., and individual contributors
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

import org.wildfly.security.auth.provider.SecurityDomain;

/**
 * A callback to acquire a security domain to perform server authentication against.  If no security domain is
 * provided, callback-based authentication is performed.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public class SecurityDomainCallback implements ExtendedCallback {
    private SecurityDomain securityDomain;

    /**
     * Construct a new instance.
     */
    public SecurityDomainCallback() {
    }

    /**
     * Get the security domain.  If none was set, {@code null} is returned.
     *
     * @return the security domain, or {@code null} if none was set
     */
    public SecurityDomain getSecurityDomain() {
        return securityDomain;
    }

    /**
     * Set the security domain.
     *
     * @param securityDomain the security domain
     */
    public void setSecurityDomain(final SecurityDomain securityDomain) {
        this.securityDomain = securityDomain;
    }

    public boolean isOptional() {
        return true;
    }

    public boolean needsInformation() {
        return true;
    }
}
