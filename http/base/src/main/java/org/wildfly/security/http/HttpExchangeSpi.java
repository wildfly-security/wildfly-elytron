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

import static org.wildfly.security.http.ElytronMessages.httpClientCert;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.security.cert.Certificate;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;

import org.wildfly.security.auth.server.SecurityIdentity;

/**
 * The SPI to be implemented to bridge the Elytron APIs with the available APIs
 * of the web server being integrated with.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public interface HttpExchangeSpi extends HttpServerScopes {

    /**
     * Get a list of all of the values set for the specified header within the HTTP request.
     *
     * @param headerName the not {@code null} name of the header the values are required for.
     * @return a list of the values set for this header, if the header is not set on the request then {@code null} should be returned.
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
     * Get the peer certificates (if any) associated with the current connection.
     *
     * Although re-negotiation may be requested the underlying implementation may not support re-negotiation and will continue
     * to return {@code null}. {@code null} will also still be returned if after re-negotiation peer certificates are still not
     * available.
     *
     * @param renegotiate if no certificates are available should re-negotiation of the session be attempted.
     * @return the peer certificates associated with the current connection or {@code null} if none associated.
     */
    default Certificate[] getPeerCertificates(boolean renegotiate) {
        SSLSession sslSession = getSSLSession();
        if (sslSession != null) {
            try {
                return sslSession.getPeerCertificates();
            } catch (SSLPeerUnverifiedException e) {
                httpClientCert.trace("Peer Unverified", e);
            }
        }

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
     *
     * @param message an error message describing the failure
     * @param mechanismName a failed mechanism name
     */
    void authenticationFailed(final String message, final String mechanismName);

    /**
     * Notification that authentication has failed for a specific mechanism due to being a bad request.
     *
     * @param error an exception to describe the error.
     * @param mechanismName a failed mechanism name
     */
    void badRequest(final HttpAuthenticationException error, final String mechanismName);

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
     * Get the request path. This is the path relative to the context path. E.g.: for a request to
     * <code>http://my.appserver.com/my-application/path/sub-path</code> this method is going to return <code>/path/sub-path</code>.
     *
     * @return the request relative path
     */
    String getRequestPath();

    /**
     * Returns the parameters received in the current request.
     *
     * These parameters will be from both the query string and the form data when available.
     *
     * Where a parameter is named both in the query string and in the form data the list will contain the values from the query
     * string followed by the values from the form data.
     *
     * @return the parameters received in the current request.
     */
    Map<String, List<String>> getRequestParameters();

    /**
     * Returns the names of all parameters either from the query string or from the form data where available.
     *
     * @return the names of all parameters either from the query string or from the form data where available.
     */
    default Set<String> getRequestParameterNames() {
        return getRequestParameters().keySet();
    }

    /**
     * Return the values for the parameter specified, where a parameter is specified both in the query string and in the form data the query string values will be first in the array.
     *
     * @param name the name of the desires parameter values.
     * @return the values for the parameter specified or {@code null} if the parameter was not in the request.
     */
    default List<String> getRequestParameterValues(String name) {
        Map<String, List<String>> parameters = getRequestParameters();
        if (parameters != null) {
            return parameters.get(name);
        }

        return null;
    }

    /**
     * Get the first value for the parameter specified.
     *
     * @param name the name of the parameter the first value is required for.
     * @return the first value of the named parameter or {@code null} if the paramter is not available.
     */
    default String getFirstRequestParameterValue(String name) {
        List<String> values = getRequestParameterValues(name);
        if (values != null && values.size() > 0) {
            return values.get(0);
        }

        return null;
    }

    /**
     * Returns a {@link List} containing all of the {@link HttpServerCookie} objects the client sent with this request. This method should return an empty {@code List} if no cookies were sent.
     *
     * @return a {@link List} of all the cookies included with this request.
     */
    List<HttpServerCookie> getCookies();

    /**
     * Returns the request input stream.
     *
     * @return the input stream or {@code null} if not supported.
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
     * @return the output stream or {@code null} if not supported.
     */
    OutputStream getResponseOutputStream();

    /**
     * Forward the current request to a different path.
     *
     * @return the desired status code from forwarding or {@code -1} if forwarding was not successful.
     */
     default int forward(String path) {
         return -1;
     }

     /**
      * Suspend the current request so that it can be subsequently resumed.
      *
      * The server may use any strategy it deems appropriate to suspend the current request and store the state ready for a subsequent request.
      *
      * @return {@code true} if suspension is supported, {@code false} otherwise.
      */
     default boolean suspendRequest() {
         return false;
     }

     /**
      * Resume a previously suspended request.
      *
      * @return {@code true} if resuming a request is supported, {@code false} otherwise.
      */
     default boolean resumeRequest() {
         return false;
     }

}
