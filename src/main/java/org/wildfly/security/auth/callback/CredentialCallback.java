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

/**
 * A callback used to acquire credentials, either for outbound or inbound authentication.  This callback
 * is required only if a default credential was not supplied.  The callback handler is expected to provide
 * a credential to this callback if one is not present.  If no credential is available, {@code null} is set, and
 * authentication may fail.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public class CredentialCallback implements ExtendedCallback {

    private Object credential;

    /**
     * Get the acquired credential.
     *
     * @return the acquired credential, or {@code null} if it wasn't set yet.
     */
    public Object getCredential() {
        return credential;
    }

    /**
     * Set the credential.
     *
     * @param credential the credential, or {@code null} if no credential is available
     */
    public void setCredential(final Object credential) {
        this.credential = credential;
    }

    public boolean isOptional() {
        return credential != null;
    }

    public boolean needsInformation() {
        return true;
    }
}
