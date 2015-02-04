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

/**
 * A callback to authorize anonymous authentication.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class AnonymousAuthorizationCallback extends AbstractExtendedCallback {

    private static final long serialVersionUID = -6532813145396004679L;

    private final String authorizationInfo;
    private boolean authorized;

    /**
     * Construct a new instance.
     *
     * @param authorizationInfo the authorization information string from the client
     */
    public AnonymousAuthorizationCallback(final String authorizationInfo) {
        this.authorizationInfo = authorizationInfo;
    }

    /**
     * Get the authorization name string from the client.  This name is only informative and <em>must not</em> be used
     * for authentication purposes.
     *
     * @return the authorization name string from the client
     */
    public String getAuthorizationInfo() {
        return authorizationInfo;
    }

    /**
     * Determine whether anonymous access was allowed by the callback handler.
     *
     * @return {@code true} if anonymous authentication was allowed, {@code false} otherwise
     */
    public boolean isAuthorized() {
        return authorized;
    }

    /**
     * Set whether anonymous access is allowed.
     *
     * @param authorized {@code true} if anonymous access is allowed, {@code false} otherwise
     */
    public void setAuthorized(final boolean authorized) {
        this.authorized = authorized;
    }

    public boolean isOptional() {
        return false;
    }

    public boolean needsInformation() {
        return true;
    }
}
