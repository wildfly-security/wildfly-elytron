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

/**
 * Enumeration of the available scopes during HTTP request handling.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public enum Scope {

    /**
     * The scope applicable to the application (or deployment) being accessed.
     */
    APPLICATION,

    /**
     * The scope applicable to the connection handling the incoming request.
     *
     */
    CONNECTION,

    /**
     * The scope applicable to the current request/response exchange.
     */
    EXCHANGE,

    /**
     * The scope applicable to the whole JVM / Process.
     */
    GLOBAL,

    /**
     * The scope applicable to any underlying session.
     */
    SESSION,

    /**
     * The scope applicable to any underlying SSL Session.
     */
    SSL_SESSION;

}
