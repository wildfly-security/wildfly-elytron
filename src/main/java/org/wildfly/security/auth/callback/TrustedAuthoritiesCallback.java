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
import java.util.List;

/**
 * An optional callback used to retrieve information about trusted certificate authorities
 * for authenticating peers.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public final class TrustedAuthoritiesCallback extends AbstractExtendedCallback {

    private static final long serialVersionUID = 1212562522733770963L;

    private Collection<List<?>> trustedAuthorities;

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
    public Collection<List<?>> getTrustedAuthorities() {
        return trustedAuthorities;
    }

    /**
     * Set the retrieved trusted authorities. The trusted authorities should be a {@code Collection}
     * of {@code List} entries where the first entry of each {@code List} is an {@code Integer}
     * (the trusted authority type, one of {@link Entity#AUTHORITY_NAME}, {@link Entity#ISSUER_NAME_HASH},
     * {@link Entity#ISSUER_KEY_HASH}, {@link Entity#AUTHORITY_CERTIFICATE} and {@link Entity#PKCS_15_KEY_HASH})
     * and the second entry is a {@code String} (the name of the trusted authority), an {@code X509Certificate}
     * (the trusted authority's certificate), or a byte array (a hash that identifies the trusted authority).
     *
     * @param trustedAuthorities the retrieved trusted authorities (may be {@code null})
     */
    public void setTrustedAuthorities(final Collection<List<?>> trustedAuthorities) {
        this.trustedAuthorities = trustedAuthorities;
    }

    public boolean needsInformation() {
        return true;
    }
}
