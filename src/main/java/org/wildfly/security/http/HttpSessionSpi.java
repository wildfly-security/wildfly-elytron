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

package org.wildfly.security.http;

import org.wildfly.security._private.ElytronMessages;

import java.util.Set;

/**
 * The SPI to be implemented to bridge the Elytron APIs with the session management capabilities provided by the underlying server.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public interface HttpSessionSpi {

    /**
     * Bare minimum implementation to indicate that session management is not supported.
     */
    HttpSessionSpi NOT_SUPPORTED = new HttpSessionSpi() {
        @Override
        public HttpServerSession getSession(boolean create) {
            throw ElytronMessages.log.httpSessionNotSupported();
        }

        @Override
        public HttpServerSession getSession(String id) {
            throw ElytronMessages.log.httpSessionNotSupported();
        }

        @Override
        public Set<String> getSessions() {
            throw ElytronMessages.log.httpSessionNotSupported();
        }
    };

    /**
     * Returns the current {@link HttpServerSession} associated with this request or, if there is no
     * current session and <code>create</code> is true, returns a new session.
     *
     * <p>If <code>create</code> is <code>false</code> and the request has no valid {@link HttpServerSession},
     * this method returns <code>null</code>.
     *
     * @param create <code>true</code> to create a new session for this request if necessary; <code>false</code> to return <code>null</code> if there's no current session
     * @return the {@link HttpServerSession} associated with this request or <code>null</code> if code>create</code> is <code>false</code> and the request has no valid session
     */
    HttpServerSession getSession(boolean create);

    /**
     * Retrieves a session with the given session id
     *
     * @param id the session ID
     * @return the session, or null if it does not exist
     */
    HttpServerSession getSession(String id);

    /**
     * Returns the identifiers of all sessions, including both active and passive
     *
     * @return the identifiers of all sessions, including both active and passive
     */
    Set<String> getSessions();
}
