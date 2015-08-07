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

import java.util.List;

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
     * Set the required response code.
     *
     * This method is only expected to be called once after a response code has been selected.
     *
     * @param responseCode the desired response code.
     */
    void setResponseCode(final int responseCode);

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


}
