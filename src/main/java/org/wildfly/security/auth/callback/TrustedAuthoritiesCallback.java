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

import java.util.Collection;

import org.wildfly.security.sasl.entity.TrustedAuthority;

/**
 * An optional callback used to retrieve information about trusted certificate authorities
 * for authenticating peers.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public final class TrustedAuthoritiesCallback extends AbstractExtendedCallback {

    private static final long serialVersionUID = 1212562522733770963L;

    private Collection<TrustedAuthority> trustedAuthorities;

    /**
     * Construct a new instance.
     */
    public TrustedAuthoritiesCallback() {
    }

    /**
     * Get the retrieved trusted authorites.
     *
     * @return the retrieved trusted authorities (may be {@code null})
     */
    public Collection<TrustedAuthority> getTrustedAuthorities() {
        return trustedAuthorities;
    }

    /**
     * Set the retrieved trusted authorities.
     *
     * @param trustedAuthorities the retrieved trusted authorities (may be {@code null})
     */
    public void setTrustedAuthorities(final Collection<TrustedAuthority> trustedAuthorities) {
        this.trustedAuthorities = trustedAuthorities;
    }

    public boolean needsInformation() {
        return true;
    }
}
