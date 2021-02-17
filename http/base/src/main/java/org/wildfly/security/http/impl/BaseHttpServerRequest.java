/*
 * Copyright 2021 Red Hat, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wildfly.security.http.impl;

import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.security.cert.Certificate;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.net.ssl.SSLSession;

import org.wildfly.security.http.HttpExchangeSpi;
import org.wildfly.security.http.HttpScope;
import org.wildfly.security.http.HttpServerCookie;
import org.wildfly.security.http.HttpServerRequest;
import org.wildfly.security.http.Scope;

/**
 * A base implementation of {@link HttpServerRequest}
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public abstract class BaseHttpServerRequest implements HttpServerRequest {

    private final HttpExchangeSpi httpExchangeSpi;

    protected BaseHttpServerRequest(final HttpExchangeSpi httpExchangeSpi) {
        this.httpExchangeSpi = httpExchangeSpi;
    }

    @Override
    public HttpScope getScope(Scope scope) {
        return httpExchangeSpi.getScope(scope);
    }

    @Override
    public Collection<String> getScopeIds(Scope scope) {
        return httpExchangeSpi.getScopeIds(scope);
    }

    @Override
    public HttpScope getScope(Scope scope, String id) {
        return httpExchangeSpi.getScope(scope, id);
    }

    @Override
    public List<String> getRequestHeaderValues(String headerName) {
        return httpExchangeSpi.getRequestHeaderValues(headerName);
    }

    @Override
    public String getFirstRequestHeaderValue(String headerName) {
        return httpExchangeSpi.getFirstRequestHeaderValue(headerName);
    }

    @Override
    public SSLSession getSSLSession() {
        return httpExchangeSpi.getSSLSession();
    }

    @Override
    public Certificate[] getPeerCertificates() {
        return httpExchangeSpi.getPeerCertificates(false);
    }

    @Override
    public String getRemoteUser() {
        return httpExchangeSpi.getRemoteUser();
    }

    @Override
    public String getRequestMethod() {
        return httpExchangeSpi.getRequestMethod();
    }

    @Override
    public URI getRequestURI() {
        return httpExchangeSpi.getRequestURI();
    }

    @Override
    public String getRequestPath() {
        return httpExchangeSpi.getRequestPath();
    }

    @Override
    public Map<String, List<String>> getParameters() {
        return httpExchangeSpi.getRequestParameters();
    }

    @Override
    public Set<String> getParameterNames() {
        return httpExchangeSpi.getRequestParameterNames();
    }

    @Override
    public List<String> getParameterValues(String name) {
        return httpExchangeSpi.getRequestParameterValues(name);
    }

    @Override
    public String getFirstParameterValue(String name) {
        return httpExchangeSpi.getFirstRequestParameterValue(name);
    }

    @Override
    public List<HttpServerCookie> getCookies() {
        return httpExchangeSpi.getCookies();
    }

    @Override
    public InputStream getInputStream() {
        return httpExchangeSpi.getRequestInputStream();
    }

    @Override
    public InetSocketAddress getSourceAddress() {
        return httpExchangeSpi.getSourceAddress();
    }

}
