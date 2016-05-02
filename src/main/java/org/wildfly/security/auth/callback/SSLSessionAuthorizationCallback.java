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

import javax.net.ssl.SSLSession;

import org.wildfly.common.Assert;

/**
 * A callback which is used to authorize an {@link SSLSession}.  The callback is responsible for examining the session
 * certificate and possibly other information, and determining whether the session should be authorized for the current
 * operation or resource.
 * <p>
 * The callback may alternatively examine the session to see if a cached authorization is valid for that session.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class SSLSessionAuthorizationCallback implements ExtendedCallback {
    private final SSLSession sslSession;
    private boolean authorized;

    /**
     * Construct a new instance.
     *
     * @param sslSession the SSL session to authorize (must not be {@code null})
     */
    public SSLSessionAuthorizationCallback(final SSLSession sslSession) {
        Assert.checkNotNullParam("sslSession", sslSession);
        this.sslSession = sslSession;
    }

    /**
     * Get the SSL session information.
     *
     * @return the SSL session information (not {@code null})
     */
    public SSLSession getSslSession() {
        return sslSession;
    }

    /**
     * Determine whether the callback handler has established that SSL session is authorized.
     *
     * @return {@code true} if the session is authorized, {@code false} otherwise
     */
    public boolean isAuthorized() {
        return authorized;
    }

    /**
     * Establish whether the SSL session is authorized.
     *
     * @param authorized {@code true} if the session is authorized, {@code false} otherwise
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
