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

import static org.wildfly.common.Assert.checkNotNullParam;

import java.util.List;

import org.wildfly.security.auth.server.SecurityIdentity;

/**
 * The Elytron representation of an exchange (request and response) being handled by a HTTP server.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public abstract class HttpServerExchange {

    private final HttpExchangeSpi httpExchangeSpi;

    HttpServerExchange(HttpExchangeSpi httpExchangeSpi) {
        this.httpExchangeSpi = httpExchangeSpi;
    }

    /**
     * Get a list of all of the values set for the specified header within the HTTP request.
     *
     * @param headerName the not {@code null} name of the header the values are required for.
     * @return a {@link List<String>} of the values set for this header, if the header is not set on the request then
     *         {@code null} should be returned.
     */
    public List<String> getRequestHeaderValues(final String headerName) {
        return httpExchangeSpi.getRequestHeaderValues(checkNotNullParam("headerName", headerName));
    }

    /**
     * Get the first value for the header specified in the HTTP request.
     *
     * @param headerName the not {@code null} name of the header the value is required for.
     * @return the value for the first instance of the header specified, if the header is not present then {@code null} should
     *         be returned instead.
     */
    public String getFirstRequestHeaderValue(final String headerName) {
        return httpExchangeSpi.getFirstRequestHeaderValue(checkNotNullParam("headerName", headerName));
    }

    /**
     * Add the specified header and value to the end of the current response headers,
     *
     * @param headerName the name of the header.
     * @param headerValue the value of the header.
     */
    public void addResponseHeader(final String headerName, final String headerValue) {
        httpExchangeSpi.addResponseHeader(headerName, headerValue);
    }

    /**
     * Set the desired response code for the current request.
     *
     * Note: If multiple mechanisms call this method then a resolution process will begin to decide which one to use.
     *
     * @param responseCode the response code.
     */
    public abstract void setResponseCode(final int responseCode);

    /**
     * Notification from an authentication mechanism that authentication has successfully been completed.
     *
     * @param securityIdentity the {@link SecurityIdentity} representing the security  identity.
     */
    public abstract void authenticationComplete(SecurityIdentity securityIdentity);

    /**
     * Notification from an authentication mechanism that authentication was attempted and failed.
     *
     * This should only be called where authentication was attempted and failed validation, normal intermediate
     * authentication steps should not call this method where a call naturally returns to the remote client.
     *
     * @param message a text description of the failure.
     */
    public abstract void authenticationFailed(final String message);

}
