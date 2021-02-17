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

package org.wildfly.security.http.util.sso;

import static org.wildfly.common.Assert.checkNotNullParam;

import org.wildfly.security.auth.server.SecurityIdentity;
import org.wildfly.security.cache.CachedIdentity;
import org.wildfly.security.cache.IdentityCache;
import org.wildfly.security.http.HttpAuthenticationException;
import org.wildfly.security.http.HttpExchangeSpi;
import org.wildfly.security.http.HttpServerCookie;
import org.wildfly.security.http.HttpServerMechanismsResponder;
import org.wildfly.security.http.HttpServerRequest;
import org.wildfly.security.http.impl.BaseHttpServerRequest;
import org.wildfly.security.http.util.SimpleHttpServerCookie;

/**
 * An implementation of {@link IdentityCache} to provide SSO for programmatic authentication.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class ProgrammaticSingleSignOnCache implements IdentityCache {

    private final HttpExchangeSpi httpExchangeSpi;
    private final String mechanismName;
    private final SingleSignOnSessionFactory singleSignOnSessionFactory;
    private final SingleSignOnConfiguration configuration;

    /*
     * Due to the nature of programmatic authentication is it very likely the three
     * methods will be called from different threads.
     */

    private volatile HttpServerRequest httpServerRequest;
    private volatile String ssoSessionId;

    ProgrammaticSingleSignOnCache(HttpExchangeSpi httpExchangeSpi, String mechanismName,
            SingleSignOnSessionFactory singleSignOnSessionFactory, SingleSignOnConfiguration configuration) {
        this.httpExchangeSpi = checkNotNullParam("httpExchangeSpi", httpExchangeSpi);
        this.mechanismName = checkNotNullParam("mechanismName", mechanismName);
        this.singleSignOnSessionFactory = checkNotNullParam("singleSignOnSessionFactory", singleSignOnSessionFactory);
        this.configuration = checkNotNullParam("configuration", configuration);
    }

    @Override
    public CachedIdentity get() {
        // This is called early for an incoming request.
        // Get the SingleSignOnSession but don't create at this point as we don't know if we will use it.
        try (SingleSignOnSession singleSignOnSession = getSingleSignOnSession(false)) {
            if (singleSignOnSession == null) {
                if (ssoSessionId != null && ssoSessionId.length() > 0) {
                    clearCookie();
                }
                return null; // No session so nothing to return from the session.
            }
            // Check if this is a logout request, if so close the session and return null.
            if (singleSignOnSession.logout()) {
                singleSignOnSession.close();
                return null; // This was a logout call, nothing else to do.
            }

            CachedIdentity cachedIdentity = singleSignOnSession.get();
            if (cachedIdentity != null && cachedIdentity.isProgrammatic()
                    && mechanismName.equals(cachedIdentity.getMechanismName())) {
                return cachedIdentity; // The identity is ours so use it.
            }

            return null;
        }
    }

    @Override
    public void put(SecurityIdentity identity) {
        try (SingleSignOnSession singleSignOnSession = getSingleSignOnSession(true)) {
            singleSignOnSession.put(identity);
            ssoSessionId = singleSignOnSession.getId();
            setCookie();
        }
    }

    @Override
    public CachedIdentity remove() {
        try (SingleSignOnSession singleSignOnSession = getSingleSignOnSession(false)) {
            if (getCookie() != null) {
                clearCookie();
            }

            if (singleSignOnSession != null) {
                return singleSignOnSession.remove();
            }
        }

        return null;
    }

    private HttpServerRequest getOrCreateHttpServerRequest() {
        if (httpServerRequest == null) {
            httpServerRequest = new SSOHttpServerRequest(httpExchangeSpi);
        }

        return httpServerRequest;
    }

    private String getSSOSessionId() {
        if (ssoSessionId == null) {
            HttpServerCookie cookie = getCookie();
            ssoSessionId = (cookie != null) ? cookie.getValue() : ""; // Use empty string so we know we queried the cookies once.
        }

        return ssoSessionId;
    }

    private SingleSignOnSession getSingleSignOnSession(boolean create) {
        String ssoSessionId = getSSOSessionId();

        SingleSignOnSession singleSignOnSession = (ssoSessionId != null && ssoSessionId.length() > 0)
                ? singleSignOnSessionFactory.find(ssoSessionId, getOrCreateHttpServerRequest())
                : null;

        if (singleSignOnSession == null && create) {
            singleSignOnSession = singleSignOnSessionFactory.create(getOrCreateHttpServerRequest(), mechanismName, true);
        }

        return singleSignOnSession;
    }

    private HttpServerCookie getCookie() {
        final String expectedCookieName = configuration.getCookieName();
        for (HttpServerCookie currentCookie : httpExchangeSpi.getCookies()) {
            if (expectedCookieName.equals(currentCookie.getName())) {
                return currentCookie;
            }
        }

        return null;
    }

    private void setCookie() {
        httpExchangeSpi.setResponseCookie(
                SimpleHttpServerCookie.newInstance(configuration.getCookieName(), ssoSessionId, configuration.getDomain(), -1,
                        configuration.getPath(), configuration.isSecure(), 0, configuration.isHttpOnly()));
    }

    private void clearCookie() {
        ssoSessionId = null;
        httpExchangeSpi.setResponseCookie(
                SimpleHttpServerCookie.newInstance(configuration.getCookieName(), null, configuration.getDomain(), 0,
                        configuration.getPath(), configuration.isSecure(), 0, configuration.isHttpOnly()));
    }

    public static IdentityCache newInstance(HttpExchangeSpi httpExchangeSpi, String mechanismName,
            SingleSignOnSessionFactory singleSignOnSessionFactory, SingleSignOnConfiguration configuration) {
        return new ProgrammaticSingleSignOnCache(httpExchangeSpi, mechanismName, singleSignOnSessionFactory, configuration);
    }

    /**
     * An implementation of {@link HttpServerRequest} which can be used with the {link SingleSignOnSessionFactory}.
     *
     * As this is only expected to be used for programmatic authentication the callback methods are not supported.
     */
    private static class SSOHttpServerRequest extends BaseHttpServerRequest {

        SSOHttpServerRequest(final HttpExchangeSpi httpExchangeSpi) {
            super(httpExchangeSpi);
        }

        @Override
        public void noAuthenticationInProgress(HttpServerMechanismsResponder responder) {
            throw new IllegalStateException();
        }

        @Override
        public void authenticationInProgress(HttpServerMechanismsResponder responder) {
            throw new IllegalStateException();
        }

        @Override
        public void authenticationComplete(HttpServerMechanismsResponder responder) {
            throw new IllegalStateException();
        }

        @Override
        public void authenticationComplete(HttpServerMechanismsResponder responder, Runnable logoutHandler) {
            throw new IllegalStateException();
        }

        @Override
        public void authenticationFailed(String message, HttpServerMechanismsResponder responder) {
            throw new IllegalStateException();
        }

        @Override
        public void badRequest(HttpAuthenticationException failure, HttpServerMechanismsResponder responder) {
            throw new IllegalStateException();
        }

        @Override
        public boolean suspendRequest() {
            throw new IllegalStateException();
        }

        @Override
        public boolean resumeRequest() {
            throw new IllegalStateException();
        }

    }

}
