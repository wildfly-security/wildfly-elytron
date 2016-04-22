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

import java.io.InputStream;
import java.net.InetSocketAddress;
import java.util.List;
import java.util.Map;

import javax.net.ssl.SSLSession;

import org.wildfly.security.auth.server.SecurityIdentity;

/**
 * Server side representation of a HTTP request.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public interface HttpServerRequest extends HttpServerScopes {

    /**
     * Get a list of all of the values set for the specified header within the HTTP request.
     *
     * @param headerName the not {@code null} name of the header the values are required for.
     * @return a {@link List<String>} of the values set for this header, if the header is not set on the request then
     *         {@code null} should be returned.
     */
    List<String> getRequestHeaderValues(final String headerName);

    /**
     * Get the first value for the header specified in the HTTP request.
     *
     * @param headerName the not {@code null} name of the header the value is required for.
     * @return the value for the first instance of the header specified, if the header is not present then {@code null} should
     *         be returned instead.
     */
    String getFirstRequestHeaderValue(final String headerName);

    /**
     * Get the {@link SSLSession} (if any) that has been established for the connection in use.
     *
     * @return the {@link SSLSession} (if any) that has been established for the connection in use, or {@code null} if none
     *         exists.
     */
    SSLSession getSSLSession();

    void noAuthenticationInProgress(final HttpServerMechanismsResponder responder);

    default void noAuthenticationInProgress() {
        noAuthenticationInProgress(null);
    }

    void authenticationInProgress(final HttpServerMechanismsResponder responder);

    default void authenticationInProgress() {
        authenticationInProgress(null);
    }

    void authenticationComplete(SecurityIdentity securityIdentity, final HttpServerMechanismsResponder responder);

    default void authenticationComplete(SecurityIdentity securityIdentity) {
        authenticationComplete(securityIdentity, null);
    }

    void authenticationFailed(final String message, final HttpServerMechanismsResponder responder);

    default void authenticationFailed(final String message) {
        authenticationFailed(message, null);
    }

    void badRequest(HttpAuthenticationException failure, final HttpServerMechanismsResponder responder);

    default void badRequest(HttpAuthenticationException failure) {
        badRequest(failure, null);
    }

    /**
     * Returns the name of the HTTP method with which this request was made, for example, GET, POST, or PUT.
     *
     * @return a <code>String</code> specifying the name of the method with which this request was made
     */
    String getRequestMethod();

    /**
     * Reconstructs the URL the client used to make the request. The returned URL contains a protocol, server name, port
     * number, and server path, but it does not include query string parameters.
     *
     * @return a <code>String</code> containing the part of the URL from the protocol name up to the query string
     */
    String getRequestURI();

    /**
     * Returns the query parameters.
     *
     * @return the query parameters
     */
    Map<String, List<String>> getParameters();

    /**
     * Returns an array containing all of the {@link HttpServerCookie} objects the client sent with this request. This method returns <code>null</code> if no cookies were sent.
     *
     * @return an array of all the cookies included with this request, or <code>null</code> if the request has no cookies
     */
    List<HttpServerCookie> getCookies();

    /**
     * Returns the request input stream.
     *
     * @return the input stream
     */
    InputStream getInputStream();

    /**
     * Get the source address of the HTTP request.
     *
     * @return the source address of the HTTP request
     */
    InetSocketAddress getSourceAddress();

}
