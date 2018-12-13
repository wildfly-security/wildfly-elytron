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

package org.wildfly.security.auth.callback;

import org.wildfly.security.credential.Credential;

/**
 * A callback to inform a server authentication mechanism of a credential which may be cached on the authentication
 * identity (if any).  The credential may be public or private.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class IdentityCredentialCallback implements ExtendedCallback {
    private final Credential credential;
    private final boolean isPrivate;

    /**
     * Construct a new instance.
     *
     * @param credential the credential (must not be {@code null})
     * @param isPrivate {@code true} if the credential should be private, {@code false} if it can be public
     */
    public IdentityCredentialCallback(final Credential credential, final boolean isPrivate) {
        this.credential = credential;
        this.isPrivate = isPrivate;
    }

    /**
     * Get the credential.
     *
     * @return the credential (not {@code null})
     */
    public Credential getCredential() {
        return credential;
    }

    /**
     * Determine whether the credential should be treated as private.
     *
     * @return {@code true} to treat the credential as private, {@code false} otherwise
     */
    public boolean isPrivate() {
        return isPrivate;
    }
}
