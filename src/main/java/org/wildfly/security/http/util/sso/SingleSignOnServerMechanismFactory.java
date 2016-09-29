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

package org.wildfly.security.http.util.sso;

import org.wildfly.security.auth.callback.CachedIdentityAuthorizeCallback;
import org.wildfly.security.auth.server.SecurityIdentity;
import org.wildfly.security.cache.CachedIdentity;
import org.wildfly.security.cache.IdentityCache;
import org.wildfly.security.http.HttpAuthenticationException;
import org.wildfly.security.http.HttpServerAuthenticationMechanism;
import org.wildfly.security.http.HttpServerAuthenticationMechanismFactory;
import org.wildfly.security.http.HttpServerCookie;
import org.wildfly.security.http.HttpServerMechanismsResponder;
import org.wildfly.security.http.HttpServerRequest;
import org.wildfly.security.http.HttpServerRequestWrapper;
import org.wildfly.security.http.HttpServerResponse;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import java.security.Principal;
import java.util.Map;

/**
 * <p>A {@link HttpServerAuthenticationMechanismFactory} which enables single sign-on to the mechanisms provided by a another
 * http mechanism factory.
 *
 * <p>The single sign-one capabilities provided by this factory is based on a HTTP Cookie to track SSO sessions and also an {@link IdentityCache} providing
 * a storage (eg.: using a shared or distributable cache/map) for these sessions and related data.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class SingleSignOnServerMechanismFactory implements HttpServerAuthenticationMechanismFactory {

    private final HttpServerAuthenticationMechanismFactory delegate;
    private final SingleSignOnConfiguration configuration;
    private final SingleSignOnSessionFactory singleSignOnSessionFactory;

    /**
     * Creates a new instance.
     *
     * @param delegate the factory holding the target mechanisms
     * @param singleSignOnSessionFactory a custom {@link SingleSignOnManager}
     * @param configuration the configuration related with the cookie representing user's session
     * @param identifierFactory a factory that will be used to create session identifiers
     */
    public SingleSignOnServerMechanismFactory(HttpServerAuthenticationMechanismFactory delegate, SingleSignOnSessionFactory singleSignOnSessionFactory, SingleSignOnConfiguration configuration) {
        this.delegate = delegate;
        this.configuration = configuration;
        this.singleSignOnSessionFactory = singleSignOnSessionFactory;
    }

    @Override
    public String[] getMechanismNames(Map<String, ?> properties) {
        return delegate.getMechanismNames(properties);
    }

    @Override
    public HttpServerAuthenticationMechanism createAuthenticationMechanism(String mechanismName, Map<String, ?> properties, CallbackHandler callbackHandler) throws HttpAuthenticationException {
        return new HttpServerAuthenticationMechanism() {
            @Override
            public String getMechanismName() {
                return mechanismName;
            }

            @Override
            public void evaluateRequest(HttpServerRequest request) throws HttpAuthenticationException {
                SingleSignOnSession singleSignOnSession = getSingleSignOnSession(request);

                if (singleSignOnSession.logout()) {
                    return;
                }

                getTargetMechanism(mechanismName, singleSignOnSession).evaluateRequest(createHttpServerRequest(request, singleSignOnSession));
            }

            private SingleSignOnSession getSingleSignOnSession(HttpServerRequest request) {
                HttpServerCookie cookie = getCookie(request);

                if (cookie == null) {
                    return singleSignOnSessionFactory.create(request, mechanismName);
                }

                String signOnSessionId = cookie.getValue();
                SingleSignOnSession singleSignOnSession = singleSignOnSessionFactory.findById(signOnSessionId, request);

                if (singleSignOnSession == null) {
                    return singleSignOnSessionFactory.create(request, mechanismName);
                }

                return singleSignOnSession;
            }

            private HttpServerAuthenticationMechanism getTargetMechanism(String mechanismName, IdentityCache identityCache) throws HttpAuthenticationException {
                return delegate.createAuthenticationMechanism(mechanismName, properties, createCallbackHandler(callbackHandler, mechanismName, identityCache));
            }

            private HttpServerRequest createHttpServerRequest(final HttpServerRequest request, SingleSignOnSession singleSignOnSession) {
                HttpServerRequest httpServerRequest = new HttpServerRequestWrapper(request) {
                    @Override
                    public void noAuthenticationInProgress(HttpServerMechanismsResponder responder) {
                        request.noAuthenticationInProgress(response -> {
                            clearCookie(request, response, singleSignOnSession);
                            if (responder != null) {
                                responder.sendResponse(response);
                            }
                        });
                    }

                    @Override
                    public void authenticationInProgress(HttpServerMechanismsResponder responder) {
                        request.authenticationInProgress(response -> {
                            clearCookie(request, response, singleSignOnSession);
                            if (responder != null) {
                                responder.sendResponse(response);
                            }
                        });
                    }

                    @Override
                    public void authenticationComplete(HttpServerMechanismsResponder responder) {
                        request.authenticationComplete(response -> {
                            String id = singleSignOnSession.getId();

                            if (id != null) {
                                HttpServerCookie cookie = getCookie(request);

                                if (cookie == null) {
                                    response.setResponseCookie(createCookie(id, -1));
                                }
                            }

                            if (responder != null) {
                                responder.sendResponse(response);
                            }
                        });
                    }

                    @Override
                    public void authenticationFailed(String message, HttpServerMechanismsResponder responder) {
                        request.authenticationFailed(message, response -> {
                            clearCookie(request, response, singleSignOnSession);
                            if (responder != null) {
                                responder.sendResponse(response);
                            }
                        });
                    }
                };

                return httpServerRequest;
            }

            private void clearCookie(HttpServerRequest request, HttpServerResponse response, IdentityCache identityCache) {
                identityCache.remove();
                if (getCookie(request) != null) {
                    response.setResponseCookie(createCookie(null, 0));
                }
            }

            HttpServerCookie getCookie(HttpServerRequest request) {
                return request.getCookies().stream().filter(current -> configuration.getCookieName().equals(current.getName())).findFirst().orElse(null);
            }

            HttpServerCookie createCookie(String value, int maxAge) {
                return new HttpServerCookie() {
                    @Override
                    public String getName() {
                        return configuration.getCookieName();
                    }

                    @Override
                    public String getValue() {
                        return value;
                    }

                    @Override
                    public String getDomain() {
                        return configuration.getDomain();
                    }

                    @Override
                    public int getMaxAge() {
                        return maxAge;
                    }

                    @Override
                    public String getPath() {
                        return configuration.getPath();
                    }

                    @Override
                    public boolean isSecure() {
                        return configuration.isSecure();
                    }

                    @Override
                    public int getVersion() {
                        return 0;
                    }

                    @Override
                    public boolean isHttpOnly() {
                        return configuration.isHttpOnly();
                    }
                };
            }
        };
    }

    private CallbackHandler createCallbackHandler(CallbackHandler callbackHandler, String mechanismName, IdentityCache identityCache) {
        return callbacks -> {
            CachedIdentity cachedIdentity = identityCache.get();
            if (cachedIdentity == null || mechanismName.equals(cachedIdentity.getMechanismName())) {
                for (int i = 0; i < callbacks.length; i++) {
                    Callback current = callbacks[i];
                    if (current instanceof CachedIdentityAuthorizeCallback) {
                        CachedIdentityAuthorizeCallback delegate = (CachedIdentityAuthorizeCallback) current;
                        if (delegate.isLocalCache()) {
                            continue;
                        }
                        Principal principal = delegate.getAuthorizationPrincipal();
                        if (principal != null) {
                            callbacks[i] = new CachedIdentityAuthorizeCallback(principal, identityCache) {
                                @Override
                                public void setAuthorized(SecurityIdentity securityIdentity) {
                                    super.setAuthorized(securityIdentity);
                                    delegate.setAuthorized(securityIdentity);
                                }
                            };
                        } else {
                            callbacks[i] = new CachedIdentityAuthorizeCallback(identityCache, delegate.isLocalCache()) {
                                @Override
                                public void setAuthorized(SecurityIdentity securityIdentity) {
                                    super.setAuthorized(securityIdentity);
                                    delegate.setAuthorized(securityIdentity);
                                }
                            };
                        }
                    }
                }
            }
            callbackHandler.handle(callbacks);
        };
    }

    public static final class SingleSignOnConfiguration {

        private final String cookieName;
        private final String domain;
        private final String path;
        private final boolean httpOnly;
        private final boolean secure;

        public SingleSignOnConfiguration(String cookieName, String domain, String path, boolean httpOnly, boolean secure) {
            this.cookieName = cookieName;
            this.domain = domain;
            this.path = path;
            this.httpOnly = httpOnly;
            this.secure = secure;
        }

        public String getCookieName() {
            return cookieName;
        }

        public String getDomain() {
            return domain;
        }

        public String getPath() {
            return path;
        }

        public boolean isSecure() {
            return secure;
        }

        public boolean isHttpOnly() {
            return httpOnly;
        }
    }
}
