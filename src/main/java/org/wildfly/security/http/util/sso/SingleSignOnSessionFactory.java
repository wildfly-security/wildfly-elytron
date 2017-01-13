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

package org.wildfly.security.http.util.sso;

import org.wildfly.security.http.HttpServerRequest;

/**
 * A factory for creating {@link SingleSignOnSession} instances.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 * @author Paul Ferraro
 */
public interface SingleSignOnSessionFactory {

    /**
     * Returns a {@link SingleSignOnSession} instance associated with the specified identifier and request.
     *
     * @param id the identifier to lookup the session
     * @param request the current request
     * @return a {@link SingleSignOnSession} instance associated with the specified identifier and request, or {@code null} if there is no session with the given identifier
     */
    SingleSignOnSession find(String id, HttpServerRequest request);

    /**
     * Creates a new {@link SingleSignOnSession} for the specified request and authentication mechanism.
     *
     * @param request the current request
     * @param mechanismName the name of the authentication mechanism
     * @return a {@link SingleSignOnSession} instance associated with the specified identifier and request
     */
    SingleSignOnSession create(HttpServerRequest request, String mechanismName);
}
