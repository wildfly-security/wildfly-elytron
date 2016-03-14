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
package org.wildfly.security.http;

import java.io.OutputStream;

/**
 * Server side representation of a HTTP response.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public interface HttpServerResponse {

    /**
     * Add the specified header and value to the end of the current response headers,
     *
     * @param headerName the name of the header.
     * @param headerValue the value of the header.
     */
    void addResponseHeader(final String headerName, final String headerValue);

    /**
     * Set the desired response code for the current request.
     *
     * Note: If multiple mechanisms call this method then a resolution process will begin to decide which one to use.
     *
     * @param responseCode the response code.
     */
    void setResponseCode(final int responseCode);

    /**
     * Sets a response cookie
     *
     * @param cookie the cookie
     */
    void setResponseCookie(final HttpServerCookie cookie);

    /**
     * Returns the output stream.
     *
     * @return the output stream
     */
    OutputStream getOutputStream();
}
