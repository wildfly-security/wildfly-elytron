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
 * Server side representation of a HTTP Cookie.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public interface HttpServerCookie {

    /**
     * Returns the name of the cookie.
     *
     * @return the name of the cookie
     */
    String getName();

    /**
     * Returns the current value of this cookie.
     *
     * @return the current value of this cookie
     */
    String getValue();

    /**
     * Gets the domain name of this cookie.
     *
     * @return the domain name of this cookie
     */
    String getDomain();

    /**
     * Gets the maximum age in seconds of this Cookie.
     *
     * @return an integer specifying the maximum age of the cookie in seconds
     */
    int getMaxAge();

    /**
     * Returns the path on the server to which the browser returns this cookie.
     *
     * @return a <code>String</code> specifying a path on the server
     */
    String getPath();

    /**
     * Returns <code>true</code> if the browser is sending cookies only over a secure protocol, or <code>false</code> if the
     * browser can send cookies using any protocol.
     *
     * @return <code>true</code> if the browser uses a secure protocol, <code>false</code> otherwise
     */
    boolean isSecure();

    /**
     * Returns the version of the protocol this cookie complies with.
     *
     * @return the version of the protocol this cookie complies with.
     */
    int getVersion();

    /**
     * Checks whether this cookie has been marked as <i>HttpOnly</i>.
     *
     * @return true if this cookie has been marked as <i>HttpOnly</i>, false otherwise
     */
    boolean isHttpOnly();
}
