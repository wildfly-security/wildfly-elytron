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

import static org.wildfly.common.Assert.checkNotNullParam;

import javax.net.ssl.SSLSession;

import org.wildfly.security.ssl.SSLConnection;

/**
 * A callback which provides information to the callback handler about the established SSLSession.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class SSLCallback implements ExtendedCallback {

    /**
     * @serial The SSL session.
     */
    private final SSLConnection sslConnection;

    /**
     * Construct a new instance.
     *
     * @param sslConnection the SSL connection (must not be {@code null})
     */
    public SSLCallback(final SSLConnection sslConnection) {
        checkNotNullParam("sslConnection", sslConnection);
        this.sslConnection = sslConnection;
    }

    /**
     * Get the SSL session in force.
     *
     * @return the SSL session in force
     */
    public SSLSession getSslSession() {
        return sslConnection.getSession();
    }

    /**
     * Get the SSL connection.
     *
     * @return the SSL connection
     */
    public SSLConnection getSslConnection() {
        return sslConnection;
    }
}
