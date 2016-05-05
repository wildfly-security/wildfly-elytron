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
import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.Set;

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

    /**
     * Notification from the mechanism to state no authentication is in progress whilst evaluating the current request.
     *
     * @param responder a {@link HttpServerMechanismsResponder} that can send a challenge should it be required.
     */
    void noAuthenticationInProgress(final HttpServerMechanismsResponder responder);

    /**
     * Notification from the mechanism to state no authentication is in progress whilst evaluating the current request.
     *
     * If this form is called no challenge is expected from this mechanism.
     */
    default void noAuthenticationInProgress() {
        noAuthenticationInProgress(null);
    }

    /**
     * Notification that this mechanism has commenced but not completed authentication, typically because another challenge /
     * response round trip is required.
     *
     * @param responder a {@link HttpServerMechanismsResponder} that can send a challenge should it be required.
     */
    void authenticationInProgress(final HttpServerMechanismsResponder responder);

    /**
     * Notification that authentication is now complete.
     *
     * After this point the framework will perform an authorization check for the authenticated user and if successful establish
     * the identity of the request.
     *
     * @param responder a {@link HttpServerMechanismsResponder} that can send a response.
     */
    void authenticationComplete(final HttpServerMechanismsResponder responder);

    /**
     * Notification that authentication is now complete.
     *
     * After this point the framework will perform an authorization check for the authenticated user and if successful establish
     * the identity of the request.
     *
     * If this form is called no response is expected from this mechanism.
     *
     * @param securityIdentity the {@link SecurityIdentity} established as a result of this authentication.
     */
    default void authenticationComplete() {
        authenticationComplete(null);
    }

    /**
     * Notification that authentication failes.
     *
     * @param message an error message describing the failure.
     * @param responder a {@link HttpServerMechanismsResponder} that can send a challenge should it be required.
     */
    void authenticationFailed(final String message, final HttpServerMechanismsResponder responder);

    /**
     * Notification that authentication failes.
     *
     * If this form is called no challenge is expected from this mechanism.
     *
     * @param message an error message describing the failure.
     */
    default void authenticationFailed(final String message) {
        authenticationFailed(message, null);
    }

    /**
     * Notification to indicate that this was a bad request.
     *
     * @param failure an {@link HttpAuthenticationException} to describe the error.
     * @param responder a {@link HttpServerMechanismsResponder} that can send a challenge should it be required.
     */
    void badRequest(HttpAuthenticationException failure, final HttpServerMechanismsResponder responder);

    /**
     * Notification to indicate that this was a bad request.
     *
     * If this form is called no challenge is expected from this mechanism.
     *
     * @param failure an {@link HttpAuthenticationException} to describe the error.
     */
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
     * Get the URI representation for the current request.
     *
     * @return the URI representation for the current request.
     */
    URI getRequestURI();

    /**
     * Returns the parameters received in the current request.
     *
     * These parameters will be from both the query string and the form data when available.
     *
     * Where a parameter is named both in the query string and in the form data the {@link List} will contain the values from the query
     * string followed by the values from the form data.
     *
     * @return the parameters received in the current request.
     */
    Map<String, List<String>> getParameters();

    /**
     * Returns the names of all parameters either from the query string or from the form data where available.
     *
     * @return the names of all parameters either from the query string or from the form data where available.
     */
    Set<String> getParameterNames();

    /**
     * Return the values for the parameter specified, where a parameter is specified both in the query string and in the form data the query string values will be first in the {@link List}.
     *
     * @param name the name of the desires parameter values.
     * @return the values for the parameter specified or {@code null} if the parameter was not in the request.
     */
    List<String> getParameterValues(String name);

    /**
     * Get the first value for the parameter specified.
     *
     * @param name the name of the parameter the first value is required for.
     * @return the first value of the named parameter or {@code null} if the paramter is not available.
     */
    String getFirstParameterValue(String name);

    /**
     * Returns a {@link List} containing all of the {@link HttpServerCookie} objects the client sent with this request, or an empty {@link List} if no cookies were included in the request.
     *
     * @return a {@link List} containing all of the {@link HttpServerCookie} objects the client sent with this request, or an empty {@link List} if no cookies were included in the request.
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
