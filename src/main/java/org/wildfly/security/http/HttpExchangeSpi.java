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
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import javax.net.ssl.SSLSession;

import org.wildfly.security.auth.server.SecurityIdentity;

/**
 * The SPI to be implemented to bridge the Elytron APIs with the available APIs
 * of the web server being integrated with.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public interface HttpExchangeSpi {

    /**
     * Get a list of all of the values set for the specified header within the HTTP request.
     *
     * @param headerName the not {@code null} name of the header the values are required for.
     * @return a {@link List<String>} of the values set for this header, if the header is not set on the request then {@code null} should be returned.
     */
    List<String> getRequestHeaderValues(final String headerName);

    /**
     * Add the specified header and value to the end of the current response headers,
     *
     * @param headerName the name of the header.
     * @param headerValue the value of the header.
     */
    void addResponseHeader(final String headerName, final String headerValue);

    /**
     * Get the first value for the header specified in the HTTP request.
     *
     * A {@code default} implementation of this method is provided although implementations of this SPI may choose to provide their own optimised implementation.
     *
     * @param headerName the not {@code null} name of the header the value is required for.
     * @return the value for the first instance of the header specified, if the header is not present then {@code null} should be returned instead.
     */
    default String getFirstRequestHeaderValue(final String headerName) {
        List<String> headerValues = getRequestHeaderValues(headerName);
        return headerValues != null && headerValues.size() > 0 ? headerValues.get(0) : null;
    }

    /**
     * Get the {@link SSLSession} (if any) that has been established for the connection in use.
     *
     * @return the {@link SSLSession} (if any) that has been established for the connection in use, or {@code null} if none
     *         exists.
     */
    default SSLSession getSSLSession() {
        return null;
    }

    /**
     * Get the {@link HttpScope} for the {@link Scope} specified.
     *
     * Note: The list of scopes could increase in future versions, implementations of this method should return {@code null} for
     * any unrecognised scope.
     *
     * @param scope the scope required.
     * @return the scope or {@code null} if it is not available.
     */
    default HttpScope getScope(Scope scope) {
        return null;
    }

    /**
     * Get the IDs of the scope specified.
     *
     * @param scope the scope the IDs are required for.
     * @return the IDs of the scope specified or {@code null} if referencing this scope by ID is not supported.
     */
    default Collection<String> getScopeIds(Scope scope) {
        return null;
    }

    /**
     * Get the {@link HttpScope} with the specific ID for the {@link Scope} specified.
     *
     * @param scope the scope required.
     * @param id the id of the required scope.
     * @return the {@link HttpScope} with the specific ID for the {@link Scope} specified, or {@code null} if it does not exist or is not supported.
     */
    default HttpScope getScope(Scope scope, String id) {
        return null;
    }

    /**
     * Set the required status code.
     *
     * This method is only expected to be called once after a response code has been selected.
     *
     * @param statusCode the desired status code.
     */
    void setStatusCode(final int statusCode);

    /**
     * Notification that authentication has been completed for a specific identity using a specific authentication mechanism.
     *
     * @param securityIdentity the identity of the authenticated account.
     * @param mechanismName the name of the mechanism that was used to authenticate the account.
     */
    void authenticationComplete(final SecurityIdentity securityIdentity, final String mechanismName);

    /**
     * Notification that authentication has failed using the mechanism specified.
     * @param message
     * @param mechanismName
     */
    void authenticationFailed(final String message, final String mechanismName);

    /**
     * Notification that authentication has failed for a specific mechanism due to being a bad request.
     * @param error
     * @param mechanismName
     */
    void badRequest(final HttpAuthenticationException error, final String mechanismName);

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
    Map<String, List<String>> getRequestParameters();

    /**
     * Returns a {@link List} containing all of the {@link HttpServerCookie} objects the client sent with this request. This method should returnan empty {@code List} if no cookies were sent.
     *
     * @return a {@link List} of all the cookies included with this request.
     */
    List<HttpServerCookie> getCookies();

    /**
     * Returns the request input stream.
     *
     * @return the input stream
     */
    InputStream getRequestInputStream();

    /**
     * Get the source address of the HTTP request.
     *
     * @return the source address of the HTTP request
     */
    InetSocketAddress getSourceAddress();

    /**
     * Sets a response cookie.
     *
     * @param cookie the cookie
     */
    void setResponseCookie(HttpServerCookie cookie);

    /**
     * Returns the response output stream.
     *
     * @return the output stream
     */
    OutputStream getResponseOutputStream();
}
