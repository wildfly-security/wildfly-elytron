/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2017 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.http.impl;

import static org.wildfly.security.auth.server.ServerUtils.ELYTRON_PASSWORD_PROVIDERS;
import static org.wildfly.security.http.HttpConstants.AUTHENTICATION_INFO;
import static org.wildfly.security.http.HttpConstants.AUTHORIZATION;
import static org.wildfly.security.http.HttpConstants.LOCATION;
import static org.wildfly.security.http.HttpConstants.WWW_AUTHENTICATE;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.cert.Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.net.ssl.SSLSession;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.AuthorizeCallback;
import javax.security.sasl.RealmCallback;

import org.hamcrest.CoreMatchers;
import org.hamcrest.MatcherAssert;
import org.junit.Assert;

import org.wildfly.security.auth.callback.AuthenticationCompleteCallback;
import org.wildfly.security.auth.callback.AvailableRealmsCallback;
import org.wildfly.security.auth.callback.CachedIdentityAuthorizeCallback;
import org.wildfly.security.auth.callback.CredentialCallback;
import org.wildfly.security.auth.callback.EvidenceVerifyCallback;
import org.wildfly.security.auth.callback.IdentityCredentialCallback;
import org.wildfly.security.auth.server.SecurityIdentity;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.evidence.PasswordGuessEvidence;
import org.wildfly.security.http.HttpAuthenticationException;
import org.wildfly.security.http.HttpExchangeSpi;
import org.wildfly.security.http.HttpScope;
import org.wildfly.security.http.HttpServerAuthenticationMechanismFactory;
import org.wildfly.security.http.HttpServerCookie;
import org.wildfly.security.http.HttpServerMechanismsResponder;
import org.wildfly.security.http.HttpServerRequest;
import org.wildfly.security.http.HttpServerResponse;
import org.wildfly.security.http.Scope;
import org.wildfly.security.http.basic.BasicMechanismFactory;
import org.wildfly.security.http.digest.DigestMechanismFactory;
import org.wildfly.security.http.digest.NonceManager;
import org.wildfly.security.http.external.ExternalMechanismFactory;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;

import mockit.Mock;
import mockit.MockUp;

// has dependency on wildfly-elytron-sasl, wildfly-elytron-http-basic and wildfly-elytron-digest
public class AbstractBaseHttpTest {

    protected HttpServerAuthenticationMechanismFactory basicFactory = new BasicMechanismFactory(ELYTRON_PASSWORD_PROVIDERS.get());
    protected HttpServerAuthenticationMechanismFactory digestFactory = new DigestMechanismFactory(ELYTRON_PASSWORD_PROVIDERS.get());
    protected final HttpServerAuthenticationMechanismFactory externalFactory = new ExternalMechanismFactory(ELYTRON_PASSWORD_PROVIDERS.get());
    protected HttpServerAuthenticationMechanismFactory statefulBasicFactory = new org.wildfly.security.http.sfbasic.BasicMechanismFactory(ELYTRON_PASSWORD_PROVIDERS.get());

    protected void mockDigestNonce(final String nonce){
        new MockUp<NonceManager>(){
            @Mock
            String generateNonce(byte[] salt) {
                return nonce;
            }
            @Mock
            boolean useNonce(final String nonce, byte[] salt, int nonceCount) {
                return true;
            }
        };
    }

    protected SecurityIdentity mockSecurityIdentity(Principal p) {
        return new MockUp<SecurityIdentity>() {
            @Mock
            public Principal getPrincipal() {
                return p;
            }
        }.getMockInstance();
    }

    protected enum Status {
        NO_AUTH,
        IN_PROGRESS,
        BAD_REQUEST,
        COMPLETE,
        FAILED;
    }

    protected static class TestingHttpServerRequest implements HttpServerRequest {

        private Status result;
        private HttpServerMechanismsResponder responder;
        private String remoteUser;
        private URI requestURI;
        private List<HttpServerCookie> cookies;
        private String requestMethod = "GET";
        private Map<String, List<String>> requestHeaders = new HashMap<>();
        private Map<String, Object> sessionScopeAttachments = new HashMap<>();

        public TestingHttpServerRequest(String[] authorization) {
            if (authorization != null) {
                requestHeaders.put(AUTHORIZATION, Arrays.asList(authorization));
            }
            this.remoteUser = null;
            this.cookies = new ArrayList<>();
        }

        public TestingHttpServerRequest(String[] authorization, URI requestURI) {
            if (authorization != null) {
                requestHeaders.put(AUTHORIZATION, Arrays.asList(authorization));
            }
            this.remoteUser = null;
            this.requestURI = requestURI;
            this.cookies = new ArrayList<>();
        }

        public TestingHttpServerRequest(String[] authorization, URI requestURI, Map<String, Object> sessionScopeAttachments) {
            if (authorization != null) {
                requestHeaders.put(AUTHORIZATION, Arrays.asList(authorization));
            }
            this.remoteUser = null;
            this.requestURI = requestURI;
            this.cookies = new ArrayList<>();
            this.sessionScopeAttachments = sessionScopeAttachments;
        }

        public TestingHttpServerRequest(String[] authorization, URI requestURI, List<HttpServerCookie> cookies) {
            if (authorization != null) {
                requestHeaders.put(AUTHORIZATION, Arrays.asList(authorization));
            }
            this.remoteUser = null;
            this.requestURI = requestURI;
            this.cookies = cookies;
        }

        public TestingHttpServerRequest(Map<String, List<String>> requestHeaders, URI requestURI, String requestMethod) {
            this.requestHeaders = requestHeaders;
            this.remoteUser = null;
            this.requestURI = requestURI;
            this.cookies = new ArrayList<>();
            this.requestMethod = requestMethod;
        }

        public TestingHttpServerRequest(String[] authorization, URI requestURI, String cookie) {
            if (authorization != null) {
                requestHeaders.put(AUTHORIZATION, Arrays.asList(authorization));
            }
            this.remoteUser = null;
            this.requestURI = requestURI;
            this.cookies = new ArrayList<>();
            if (cookie != null) {
                final String cookieName = cookie.substring(0, cookie.indexOf('='));
                final String cookieValue = cookie.substring(cookie.indexOf('=') + 1);
                cookies.add(new HttpServerCookie() {
                    @Override
                    public String getName() {
                        return cookieName;
                    }

                    @Override
                    public String getValue() {
                        return cookieValue;
                    }

                    @Override
                    public String getDomain() {
                        return null;
                    }

                    @Override
                    public int getMaxAge() {
                        return -1;
                    }

                    @Override
                    public String getPath() {
                        return "/";
                    }

                    @Override
                    public boolean isSecure() {
                        return false;
                    }

                    @Override
                    public int getVersion() {
                        return 0;
                    }

                    @Override
                    public boolean isHttpOnly() {
                        return true;
                    }
                });
            }
        }


        public Status getResult() {
            return result;
        }

        public TestingHttpServerResponse getResponse() throws HttpAuthenticationException {
            TestingHttpServerResponse response = new TestingHttpServerResponse();
            responder.sendResponse(response);
            return response;
        }

        public List<String> getRequestHeaderValues(String headerName) {
            return requestHeaders.get(headerName);
        }

        public String getFirstRequestHeaderValue(String headerName) {
            List<String> headerValues = requestHeaders.get(headerName);
            return headerValues != null ? headerValues.get(0) : null;
        }

        public SSLSession getSSLSession() {
            throw new IllegalStateException();
        }

        public Certificate[] getPeerCertificates() {
            throw new IllegalStateException();
        }

        public void noAuthenticationInProgress(HttpServerMechanismsResponder responder) {
            result = Status.NO_AUTH;
            this.responder = responder;
        }

        public void authenticationInProgress(HttpServerMechanismsResponder responder) {
            result = Status.IN_PROGRESS;
            this.responder = responder;
        }

        public void authenticationComplete(HttpServerMechanismsResponder responder) {
            result = Status.COMPLETE;
            this.responder = responder;
        }

        public void authenticationComplete(HttpServerMechanismsResponder responder, Runnable logoutHandler) {
            result = Status.COMPLETE;
            this.responder = responder;
        }

        public void authenticationFailed(String message, HttpServerMechanismsResponder responder) {
            result = Status.FAILED;
            this.responder = responder;
        }

        public void badRequest(HttpAuthenticationException failure, HttpServerMechanismsResponder responder) {
            throw new IllegalStateException();
        }

        public String getRequestMethod() {
            return requestMethod;
        }

        public URI getRequestURI() {
            return requestURI;
        }

        public String getRequestPath() {
            throw new IllegalStateException();
        }

        public Map<String, List<String>> getParameters() {
            throw new IllegalStateException();
        }

        public Set<String> getParameterNames() {
            throw new IllegalStateException();
        }

        public List<String> getParameterValues(String name) {
            throw new IllegalStateException();
        }

        public String getFirstParameterValue(String name) {
            throw new IllegalStateException();
        }

        public List<HttpServerCookie> getCookies() {
            return cookies;
        }

        public InputStream getInputStream() {
            throw new IllegalStateException();
        }

        public InetSocketAddress getSourceAddress() {
            return null;
        }

        public boolean suspendRequest() {
            return true;
        }

        public boolean resumeRequest() {
            return true;
        }

        public HttpScope getScope(Scope scope) {
            return new HttpScope() {

                @Override
                public boolean exists() {
                    return true;
                }

                @Override
                public boolean create() {
                    return false;
                }

                @Override
                public boolean supportsAttachments() {
                    return true;
                }

                @Override
                public boolean supportsInvalidation() {
                    return false;
                }

                @Override
                public void setAttachment(String key, Object value) {
                    if (scope.equals(Scope.SESSION)) {
                        sessionScopeAttachments.put(key, value);
                    }
                }

                @Override
                public Object getAttachment(String key) {
                    if (scope.equals(Scope.SESSION)) {
                        return sessionScopeAttachments.get(key);
                    } else {
                        return null;
                    }
                }

            };
        }

        public Collection<String> getScopeIds(Scope scope) {
            throw new IllegalStateException();
        }

        public HttpScope getScope(Scope scope, String id) {
            throw new IllegalStateException();
        }

        public void setRemoteUser (String remoteUser) {
            this.remoteUser = remoteUser;
        }

        @Override
        public String getRemoteUser() {
            return remoteUser;
        }

        public Map<String, Object> getSessionScopeAttachments() {
            return sessionScopeAttachments;
        }
    }

    protected static class TestingHttpServerResponse implements HttpServerResponse {

        private int statusCode;
        private List<HttpServerCookie> cookies;
        private Map<String, List<String>> responseHeaders = new HashMap<>();

        public void setStatusCode(int statusCode) {
            this.statusCode = statusCode;
        }

        public int getStatusCode() {
            return statusCode;
        }

        public void addResponseHeader(String headerName, String headerValue) {
            if (headerValue != null) {
                responseHeaders.put(headerName, Collections.singletonList(headerValue));
            }
        }

        public String getAuthenticateHeader() {
            return getFirstResponseHeaderValue(WWW_AUTHENTICATE);
        }

        public String getLocation() {
            return getFirstResponseHeaderValue(LOCATION);
        }

        public String getFirstResponseHeaderValue(String headerName) {
            List<String> headerValue = responseHeaders.get(headerName);
            return headerValue == null ? null : headerValue.get(0);
        }

        public List<HttpServerCookie> getCookies() {
            return cookies;
        }

        public void setResponseCookie(HttpServerCookie cookie) {
            if (cookies == null) {
                cookies = new ArrayList<>();
            }
            cookies.add(cookie);
        }

        public OutputStream getOutputStream() {
            throw new IllegalStateException();
        }

        public boolean forward(String path) {
            throw new IllegalStateException();
        }
    }

    protected CallbackHandler getCallbackHandler(String username, String realm, String password) {
        return callbacks -> {
            for(Callback callback : callbacks) {
                if (callback instanceof AvailableRealmsCallback) {
                    ((AvailableRealmsCallback) callback).setRealmNames(realm);
                } else if (callback instanceof RealmCallback) {
                    Assert.assertEquals(realm, ((RealmCallback) callback).getDefaultText());
                } else if (callback instanceof NameCallback) {
                    Assert.assertEquals(username, ((NameCallback) callback).getDefaultName());
                } else if (callback instanceof CredentialCallback) {
                    if (!ClearPassword.ALGORITHM_CLEAR.equals(((CredentialCallback) callback).getAlgorithm())) {
                        throw new UnsupportedCallbackException(callback);
                    }
                    try {
                        PasswordFactory factory = PasswordFactory.getInstance(ClearPassword.ALGORITHM_CLEAR, ELYTRON_PASSWORD_PROVIDERS);
                        Password pass = factory.generatePassword(new ClearPasswordSpec(password.toCharArray()));
                        ((CredentialCallback) callback).setCredential(new PasswordCredential(pass));
                    } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                        throw new IllegalStateException(e);
                    }
                } else if (callback instanceof EvidenceVerifyCallback) {
                    PasswordGuessEvidence evidence = (PasswordGuessEvidence) ((EvidenceVerifyCallback) callback).getEvidence();
                    ((EvidenceVerifyCallback) callback).setVerified(Arrays.equals(evidence.getGuess(), password.toCharArray()));
                    evidence.destroy();
                } else if (callback instanceof AuthenticationCompleteCallback) {
                    // NO-OP
                } else if (callback instanceof IdentityCredentialCallback) {
                    Credential credential = ((IdentityCredentialCallback) callback).getCredential();
                    MatcherAssert.assertThat(credential, CoreMatchers.instanceOf(PasswordCredential.class));
                    ClearPassword clearPwdCredential = ((PasswordCredential) credential).getPassword().castAs(ClearPassword.class);
                    Assert.assertNotNull(clearPwdCredential);
                    Assert.assertArrayEquals(password.toCharArray(), clearPwdCredential.getPassword());
                } else if (callback instanceof AuthorizeCallback) {
                    if(username.equals(((AuthorizeCallback) callback).getAuthenticationID()) &&
                       username.equals(((AuthorizeCallback) callback).getAuthorizationID())) {
                        ((AuthorizeCallback) callback).setAuthorized(true);
                    } else {
                        ((AuthorizeCallback) callback).setAuthorized(false);
                    }
                } else if (callback instanceof CachedIdentityAuthorizeCallback) {
                    CachedIdentityAuthorizeCallback ciac = (CachedIdentityAuthorizeCallback) callback;
                    if(ciac.getAuthorizationPrincipal() != null &&
                            username.equals(ciac.getAuthorizationPrincipal().getName())) {
                        ciac.setAuthorized(mockSecurityIdentity(ciac.getAuthorizationPrincipal()));
                    } else if (ciac.getIdentity() != null && username.equals(ciac.getIdentity().getPrincipal().getName())) {
                        ciac.setAuthorized(ciac.getIdentity());
                    } else {
                        ciac.setAuthorized(null);
                    }
                } else {
                    throw new UnsupportedCallbackException(callback);
                }
            }
        };
    }

    public class TestingHttpExchangeSpi implements HttpExchangeSpi {

        private Map<String, List<String>> requestHeaders = new HashMap<>();
        private List<String> responseAuthenticateHeaders = new LinkedList<>();
        private List<String> responseAuthenticationInfoHeaders = new LinkedList<>();
        private int statusCode;
        private Status result;
        private String requestMethod = "GET";

        public int getStatusCode() {
            return statusCode;
        }

        public Status getResult() {
            return result;
        }

        public List<String> getResponseAuthenticateHeaders() {
            return responseAuthenticateHeaders;
        }

        public List<String> getResponseAuthenticationInfoHeaders() {
            return responseAuthenticationInfoHeaders;
        }

        public void setRequestAuthorizationHeaders(List<String> requestAuthorizationHeaders) {
            requestHeaders.put(AUTHORIZATION, requestAuthorizationHeaders);
        }

        public void setHeader(String headerName, String headerValue) {
            if (headerValue != null) {
                setHeader(headerName, Collections.singletonList(headerValue));
            }
        }

        public void setHeader(String headerName, List<String> headerValue) {
            requestHeaders.put(headerName, headerValue);
        }

        public void setRequestMethod(String requestMethod) {
            this.requestMethod = requestMethod;
        }

        // ------

        public List<String> getRequestHeaderValues(String headerName) {
            return requestHeaders.get(headerName);
        }

        public void addResponseHeader(String headerName, String headerValue) {
            if (WWW_AUTHENTICATE.equals(headerName)) {
                responseAuthenticateHeaders.add(headerValue);
            } else if (AUTHENTICATION_INFO.equals(headerName)) {
                responseAuthenticationInfoHeaders.add(headerValue);
            } else {
                throw new IllegalStateException();
            }
        }

        public void setStatusCode(int statusCode) {
            this.statusCode = statusCode;
        }

        public void authenticationComplete(SecurityIdentity securityIdentity, String mechanismName) {
            result = Status.COMPLETE;
        }

        public void authenticationFailed(String message, String mechanismName) {
            result = Status.FAILED;
        }

        public void badRequest(HttpAuthenticationException error, String mechanismName) {
            result = Status.BAD_REQUEST;
        }

        public String getRequestMethod() {
            return requestMethod;
        }

        public URI getRequestURI() {
            throw new IllegalStateException();
        }

        public String getRequestPath() {
            throw new IllegalStateException();
        }

        public Map<String, List<String>> getRequestParameters() {
            throw new IllegalStateException();
        }

        public List<HttpServerCookie> getCookies() {
            throw new IllegalStateException();
        }

        public InputStream getRequestInputStream() {
            throw new IllegalStateException();
        }

        public InetSocketAddress getSourceAddress() {
            throw new IllegalStateException();
        }

        public void setResponseCookie(HttpServerCookie cookie) {
            throw new IllegalStateException();
        }

        public OutputStream getResponseOutputStream() {
            throw new IllegalStateException();
        }

        public HttpScope getScope(Scope scope) {
            throw new IllegalStateException();
        }

        public Collection<String> getScopeIds(Scope scope) {
            throw new IllegalStateException();
        }

        public HttpScope getScope(Scope scope, String id) {
            throw new IllegalStateException();
        }
    }

}
