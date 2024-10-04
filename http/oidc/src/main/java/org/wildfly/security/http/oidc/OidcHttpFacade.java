/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2020 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.wildfly.security.http.oidc;

import static org.wildfly.security.http.oidc.ElytronMessages.log;
import static org.wildfly.security.http.oidc.Oidc.HTML_CONTENT_TYPE;

import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;

import java.security.Principal;
import java.security.cert.Certificate;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.function.Supplier;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.AuthorizeCallback;

import org.wildfly.security.auth.callback.AuthenticationCompleteCallback;
import org.wildfly.security.auth.callback.EvidenceVerifyCallback;
import org.wildfly.security.auth.callback.IdentityCredentialCallback;
import org.wildfly.security.auth.callback.SecurityIdentityCallback;
import org.wildfly.security.auth.server.SecurityIdentity;
import org.wildfly.security.credential.BearerTokenCredential;
import org.wildfly.security.evidence.Evidence;
import org.wildfly.security.http.HttpAuthenticationException;
import org.wildfly.security.http.HttpScope;
import org.wildfly.security.http.HttpServerCookie;
import org.wildfly.security.http.HttpServerRequest;
import org.wildfly.security.http.HttpServerResponse;
import org.wildfly.security.http.Scope;

/**
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public class OidcHttpFacade {

    private final HttpServerRequest request;
    private final CallbackHandler callbackHandler;
    private final OidcTokenStore tokenStore;
    private final OidcClientContext oidcClientContext;
    private Consumer<HttpServerResponse> responseConsumer;
    private OidcAccount account;
    private SecurityIdentity securityIdentity;
    private boolean restored;
    private final Map<String, String> headers = new HashMap<>();

    public OidcHttpFacade(HttpServerRequest request, OidcClientContext oidcClientContext, CallbackHandler handler) {
        this.request = request;
        this.oidcClientContext = oidcClientContext;
        this.callbackHandler = handler;
        this.tokenStore = createTokenStore();
        this.responseConsumer = response -> {};
    }

    void authenticationComplete(OidcAccount account, boolean storeToken) {
        this.securityIdentity = authorize(this.callbackHandler, account.getPrincipal());
        if (securityIdentity != null) {
            this.account = account;
            RefreshableOidcSecurityContext securityContext = account.getOidcSecurityContext();
            account.setCurrentRequestInfo(securityContext.getOidcClientConfiguration(), this.tokenStore);
            if (storeToken) {
                this.tokenStore.saveAccountInfo(account);
            }
        }
    }

    static final SecurityIdentity authorize(CallbackHandler callbackHandler, Principal principal) {
        try {
            EvidenceVerifyCallback evidenceVerifyCallback = new EvidenceVerifyCallback(new Evidence() {
                @Override
                public Principal getPrincipal() {
                    return principal;
                }
            });

            callbackHandler.handle(new Callback[]{evidenceVerifyCallback});
            if (evidenceVerifyCallback.isVerified()) {
                AuthorizeCallback authorizeCallback = new AuthorizeCallback(null, null);
                try {
                    callbackHandler.handle(new Callback[] {authorizeCallback});
                    authorizeCallback.isAuthorized();
                } catch (Exception e) {
                    throw new HttpAuthenticationException(e);
                }
                SecurityIdentityCallback securityIdentityCallback = new SecurityIdentityCallback();
                IdentityCredentialCallback credentialCallback = new IdentityCredentialCallback(new BearerTokenCredential(OidcPrincipal.class.cast(principal).getOidcSecurityContext().getTokenString()), true);
                callbackHandler.handle(new Callback[]{credentialCallback, AuthenticationCompleteCallback.SUCCEEDED, securityIdentityCallback});
                return securityIdentityCallback.getSecurityIdentity();
           }
        } catch (UnsupportedCallbackException | IOException e) {
            throw new RuntimeException(e);
        }
        return null;
    }

    void authenticationComplete() {
        if (securityIdentity != null) {
            HttpScope requestScope = request.getScope(Scope.EXCHANGE);
            RefreshableOidcSecurityContext securityContext = account.getOidcSecurityContext();

            requestScope.setAttachment(OidcSecurityContext.class.getName(), securityContext);

            this.request.authenticationComplete(response -> {
                if (!restored) {
                    responseConsumer.accept(response);
                }
            }, () -> tokenStore.logout(true));
        }
    }

    void authenticationFailed() {
        this.request.authenticationFailed("Authentication Failed", response -> responseConsumer.accept(response));
    }

    void noAuthenticationInProgress() {
        this.request.noAuthenticationInProgress();
    }

    void noAuthenticationInProgress(AuthChallenge challenge) {
        if (challenge != null) {
            challenge.challenge(this);
        }
        this.request.noAuthenticationInProgress(response -> responseConsumer.accept(response));
    }

    void authenticationInProgress() {
        this.request.authenticationInProgress(response -> responseConsumer.accept(response));
    }

    HttpScope getScope(Scope scope) {
        return request.getScope(scope);
    }

    HttpScope getScope(Scope scope, String id) {
        return request.getScope(scope, id);
    }

    Collection<String> getScopeIds(Scope scope) {
        return request.getScopeIds(scope);
    }

    OidcTokenStore getTokenStore() {
        return this.tokenStore;
    }

    OidcClientConfiguration getOidcClientConfiguration() {
        return oidcClientContext.resolveDeployment(this);
    }

    private OidcTokenStore createTokenStore() {
        OidcClientConfiguration deployment = getOidcClientConfiguration();

        if (Oidc.TokenStore.SESSION.equals(deployment.getTokenStore())) {
            return new OidcSessionTokenStore(this);
        } else {
            return new OidcCookieTokenStore(this);
        }
    }

    public Request getRequest() {
        return new Request() {
            private InputStream inputStream;

            @Override
            public String getMethod() {
                return request.getRequestMethod();
            }

            @Override
            public String getURI() {
                return request.getRequestURI().toString();
            }

            @Override
            public String getRelativePath() {
                return request.getRequestPath();
            }

            @Override
            public boolean isSecure() {
                return request.getRequestURI().getScheme().equals("https");
            }

            @Override
            public String getFirstParam(String param) {
                return request.getFirstParameterValue(param);
            }

            @Override
            public String getQueryParamValue(String param) {
                URI requestURI = request.getRequestURI();
                String query = requestURI.getQuery();
                if (query != null) {
                    String[] parameters = query.split("&");
                    for (String parameter : parameters) {
                        String[] keyValue = parameter.split("=", 2);
                        if (keyValue[0].equals(param)) {
                            try {
                                return URLDecoder.decode(keyValue[1], "UTF-8");
                            } catch (IOException e) {
                                throw log.failedToDecodeRequestUri(e);
                            }
                        }
                    }
                }
                return null;
            }

            @Override
            public Cookie getCookie(final String cookieName) {
                List<HttpServerCookie> cookies = request.getCookies();

                if (cookies != null) {
                    for (HttpServerCookie cookie : cookies) {
                        if (cookie.getName().equals(cookieName)) {
                            return new Cookie(cookie.getName(), cookie.getValue(), cookie.getVersion(), cookie.getDomain(), cookie.getPath());
                        }
                    }
                }

                return null;
            }

            @Override
            public String getHeader(String name) {
                return request.getFirstRequestHeaderValue(name);
            }

            @Override
            public List<String> getHeaders(String name) {
                return request.getRequestHeaderValues(name);
            }

            @Override
            public InputStream getInputStream() {
                return getInputStream(false);
            }

            @Override
            public InputStream getInputStream(boolean buffered) {
                if (inputStream != null) {
                    return inputStream;
                }

                if (buffered) {
                    inputStream = new BufferedInputStream(request.getInputStream());
                    Supplier<InputStream> inputStreamSupplier = () -> {
                        inputStream.mark(0);
                        return new ServletInputStream() {
                            @Override
                            public int read() throws IOException {
                                return inputStream.read();
                            }

                            @Override
                            public boolean isFinished() {
                                try {
                                    return inputStream.available() == 0;
                                } catch (IOException e) {
                                    return true;
                                }
                            }

                            @Override
                            public boolean isReady() {
                                return true;
                            }

                            @Override
                            public void setReadListener(ReadListener listener) {
                                throw new UnsupportedOperationException();
                            }
                        };
                    };
                    request.setRequestInputStreamSupplier(inputStreamSupplier);
                    return inputStream;
                }
                return request.getInputStream();
            }

            @Override
            public String getRemoteAddr() {
                InetSocketAddress sourceAddress = request.getSourceAddress();
                if (sourceAddress == null) {
                    return "";
                }
                InetAddress address = sourceAddress.getAddress();
                if (address == null) {
                    // this is unresolved, so we just return the host name not exactly spec, but if the name should be
                    // resolved then a PeerNameResolvingHandler should be used and this is probably better than just
                    // returning null
                    return sourceAddress.getHostString();
                }
                return address.getHostAddress();
            }

            @Override
            public void setError(AuthenticationError error) {
                request.getScope(Scope.EXCHANGE).setAttachment(AuthenticationError.class.getName(), error);
            }

            @Override
            public void setError(LogoutError error) {
                request.getScope(Scope.EXCHANGE).setAttachment(LogoutError.class.getName(), error);
            }
        };
    }

    public Response getResponse() {
        return new Response() {

            @Override
            public void setStatus(final int status) {
                if (status < 200 || status > 300) {
                    responseConsumer = responseConsumer.andThen(response -> response.setStatusCode(status));
                }
            }

            @Override
            public void addHeader(final String name, final String value) {
                headers.put(name, value);
                responseConsumer = responseConsumer.andThen(new Consumer<HttpServerResponse>() {
                    @Override
                    public void accept(HttpServerResponse response) {
                        String latestValue = headers.get(name);

                        if (latestValue.equals(value)) {
                            response.addResponseHeader(name, latestValue);
                        }
                    }
                });
            }

            @Override
            public void setHeader(String name, String value) {
                addHeader(name, value);
            }

            @Override
            public void resetCookie(final String name, final String path) {
                responseConsumer = responseConsumer.andThen(response -> setCookie(name, "", path, null, 0, false, false, response));
            }

            @Override
            public void setCookie(final String name, final String value, final String path, final String domain, final int maxAge, final boolean secure, final boolean httpOnly) {
                responseConsumer = responseConsumer.andThen(response -> setCookie(name, value, path, domain, maxAge, secure, httpOnly, response));
            }

            private void setCookie(final String name, final String value, final String path, final String domain, final int maxAge, final boolean secure, final boolean httpOnly, HttpServerResponse response) {
                response.setResponseCookie(HttpServerCookie.getInstance(name, value, domain, maxAge, path, secure, 0, httpOnly));
            }

            @Override
            public OutputStream getOutputStream() {
                ByteArrayOutputStream stream = new ByteArrayOutputStream();
                responseConsumer = responseConsumer.andThen(new Consumer<HttpServerResponse>() {
                    @Override
                    public void accept(HttpServerResponse httpServerResponse) {
                        try {
                            httpServerResponse.getOutputStream().write(stream.toByteArray());
                        } catch (IOException e) {
                            throw log.failedToWriteToResponseOutputStream(e);
                        }
                    }
                });
                return stream;
            }

            @Override
            public void sendError(int code) {
                setStatus(code);
            }

            @Override
            public void sendError(final int code, final String message) {
                responseConsumer = responseConsumer.andThen(response -> {
                    response.setStatusCode(code);
                    response.addResponseHeader("Content-Type", HTML_CONTENT_TYPE);
                    try {
                        response.getOutputStream().write(message.getBytes());
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                });
            }

            @Override
            public void end() {

            }
        };
    }

    public Certificate[] getCertificateChain() {
        return request.getPeerCertificates();
    }

    public OidcSecurityContext getSecurityContext() {
        if (account == null) {
            return null;
        }
        return this.account.getOidcSecurityContext();
    }

    public boolean restoreRequest() {
        restored = this.request.resumeRequest();
        return restored;
    }

    public void suspendRequest() {
        responseConsumer = responseConsumer.andThen(httpServerResponse -> request.suspendRequest());
    }

    public boolean isAuthorized() {
        return this.securityIdentity != null;
    }

    public interface Request {

        String getMethod();
        /**
         * Full request URI with query params
         *
         * @return
         */
        String getURI();

        /**
         * Get the request relative path.
         *
         * @return the request relative path
         */
        String getRelativePath();

        /**
         * HTTPS?
         *
         * @return
         */
        boolean isSecure();

        /**
         * Get first query or form param
         *
         * @param param
         * @return
         */
        String getFirstParam(String param);
        String getQueryParamValue(String param);
        Cookie getCookie(String cookieName);
        String getHeader(String name);
        List<String> getHeaders(String name);
        InputStream getInputStream();
        InputStream getInputStream(boolean buffered);

        String getRemoteAddr();
        void setError(AuthenticationError error);
        void setError(LogoutError error);
    }

    public interface Response {
        void setStatus(int status);
        void addHeader(String name, String value);
        void setHeader(String name, String value);
        void resetCookie(String name, String path);
        void setCookie(String name, String value, String path, String domain, int maxAge, boolean secure, boolean httpOnly);
        OutputStream getOutputStream();
        void sendError(int code);
        void sendError(int code, String message);

        /**
         * If the response is finished, end it.
         *
         */
        void end();
    }

    public class Cookie {
        protected String name;
        protected String value;
        protected int version;
        protected String domain;
        protected String path;

        public Cookie(String name, String value, int version, String domain, String path) {
            this.name = name;
            this.value = value;
            this.version = version;
            this.domain = domain;
            this.path = path;
        }

        public String getName() {
            return name;
        }

        public String getValue() {
            return value;
        }

        public int getVersion() {
            return version;
        }

        public String getDomain() {
            return domain;
        }

        public String getPath() {
            return path;
        }
    }
}
