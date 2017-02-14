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

import org.wildfly.common.Assert;

import javax.net.ssl.SSLSession;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class HttpServerRequestWrapper implements HttpServerRequest {

    private final HttpServerRequest delegate;

    public HttpServerRequestWrapper(HttpServerRequest delegate) {
        Assert.checkNotNullParam("delegate", delegate);
        this.delegate = delegate;
    }

    @Override
    public HttpScope getScope(Scope scope) {
        return delegate.getScope(scope);
    }

    @Override
    public Collection<String> getScopeIds(Scope scope) {
        return delegate.getScopeIds(scope);
    }

    @Override
    public HttpScope getScope(Scope scope, String id) {
        return delegate.getScope(scope, id);
    }

    @Override
    public List<String> getRequestHeaderValues(String headerName) {
        return delegate.getRequestHeaderValues(headerName);
    }

    @Override
    public String getFirstRequestHeaderValue(String headerName) {
        return delegate.getFirstRequestHeaderValue(headerName);
    }

    @Override
    public SSLSession getSSLSession() {
        return delegate.getSSLSession();
    }

    @Override
    public void noAuthenticationInProgress(HttpServerMechanismsResponder responder) {
        delegate.noAuthenticationInProgress(responder);
    }

    @Override
    public void authenticationInProgress(HttpServerMechanismsResponder responder) {
        delegate.authenticationInProgress(responder);
    }

    @Override
    public void authenticationComplete(HttpServerMechanismsResponder responder) {
        delegate.authenticationComplete(responder);
    }

    @Override
    public void authenticationFailed(String message, HttpServerMechanismsResponder responder) {
        delegate.authenticationFailed(message, responder);
    }

    @Override
    public void badRequest(HttpAuthenticationException failure, HttpServerMechanismsResponder responder) {
        delegate.badRequest(failure, responder);
    }

    @Override
    public String getRequestMethod() {
        return delegate.getRequestMethod();
    }

    @Override
    public URI getRequestURI() {
        return delegate.getRequestURI();
    }

    @Override
    public String getRequestPath() {
        return delegate.getRequestPath();
    }

    @Override
    public Map<String, List<String>> getParameters() {
        return delegate.getParameters();
    }

    @Override
    public Set<String> getParameterNames() {
        return delegate.getParameterNames();
    }

    @Override
    public List<String> getParameterValues(String name) {
        return delegate.getParameterValues(name);
    }

    @Override
    public String getFirstParameterValue(String name) {
        return delegate.getFirstParameterValue(name);
    }

    @Override
    public List<HttpServerCookie> getCookies() {
        return delegate.getCookies();
    }

    @Override
    public InputStream getInputStream() {
        return delegate.getInputStream();
    }

    @Override
    public InetSocketAddress getSourceAddress() {
        return delegate.getSourceAddress();
    }

    @Override
    public boolean suspendRequest() {
        return delegate.suspendRequest();
    }

    @Override
    public boolean resumeRequest() {
        return delegate.resumeRequest();
    }
}
