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

import mockit.Mock;
import mockit.MockUp;
import org.junit.Assert;
import org.wildfly.security.auth.callback.AuthenticationCompleteCallback;
import org.wildfly.security.auth.callback.AvailableRealmsCallback;
import org.wildfly.security.auth.callback.CredentialCallback;
import org.wildfly.security.auth.callback.EvidenceVerifyCallback;
import org.wildfly.security.auth.callback.IdentityCredentialCallback;
import org.wildfly.security.auth.server.SecurityIdentity;
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
import org.wildfly.security.http.external.ExternalMechanismFactory;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.sasl.test.BaseTestCase;
import org.wildfly.security.http.basic.BasicMechanismFactory;
import org.wildfly.security.http.digest.DigestMechanismFactory;
import org.wildfly.security.http.digest.NonceManager;

import javax.net.ssl.SSLSession;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.AuthorizeCallback;
import javax.security.sasl.RealmCallback;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.wildfly.security.http.HttpConstants.AUTHENTICATION_INFO;
import static org.wildfly.security.http.HttpConstants.AUTHORIZATION;
import static org.wildfly.security.http.HttpConstants.WWW_AUTHENTICATE;

// has dependency on wildfly-elytron-sasl, wildfly-elytron-http-basic and wildfly-elytron-digest
public class AbstractBaseHttpTest extends BaseTestCase {

    protected HttpServerAuthenticationMechanismFactory basicFactory = new BasicMechanismFactory();
    protected HttpServerAuthenticationMechanismFactory digestFactory = new DigestMechanismFactory();
    protected final HttpServerAuthenticationMechanismFactory externalFactory = new ExternalMechanismFactory();

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

    protected enum Status {
        NO_AUTH,
        IN_PROGRESS,
        BAD_REQUEST,
        COMPLETE,
        FAILED;
    }

    protected class TestingHttpServerRequest implements HttpServerRequest {

        private String[] authorization;
        private Status result;
        private HttpServerMechanismsResponder responder;
        private String remoteUser;

        public TestingHttpServerRequest(String[] authorization) {
            this.authorization = authorization;
            this.remoteUser = null;
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
            if (AUTHORIZATION.equals(headerName)) {
                return authorization == null ? null : Arrays.asList(authorization);
            }
            return null;
        }

        public String getFirstRequestHeaderValue(String headerName) {
            throw new IllegalStateException();
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
            throw new IllegalStateException();
        }

        public void authenticationFailed(String message, HttpServerMechanismsResponder responder) {
            result = Status.FAILED;
            this.responder = responder;
        }

        public void badRequest(HttpAuthenticationException failure, HttpServerMechanismsResponder responder) {
            throw new IllegalStateException();
        }

        public String getRequestMethod() {
            return "GET";
        }

        public URI getRequestURI() {
            throw new IllegalStateException();
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
            throw new IllegalStateException();
        }

        public InputStream getInputStream() {
            throw new IllegalStateException();
        }

        public InetSocketAddress getSourceAddress() {
            throw new IllegalStateException();
        }

        public boolean suspendRequest() {
            throw new IllegalStateException();
        }

        public boolean resumeRequest() {
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

        public void setRemoteUser (String remoteUser) {
            this.remoteUser = remoteUser;
        }

        @Override
        public String getRemoteUser() {
            return remoteUser;
        }
    }

    protected class TestingHttpServerResponse implements HttpServerResponse {

        private int statusCode;
        private String authenticate;

        public void setStatusCode(int statusCode) {
            this.statusCode = statusCode;
        }

        public int getStatusCode() {
            return statusCode;
        }

        public void addResponseHeader(String headerName, String headerValue) {
            if (WWW_AUTHENTICATE.equals(headerName)) {
                authenticate = headerValue;
            } else {
                throw new IllegalStateException();
            }
        }

        public String getAuthenticateHeader() {
            return authenticate;
        }

        public void setResponseCookie(HttpServerCookie cookie) {
            throw new IllegalStateException();
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
                        PasswordFactory factory = PasswordFactory.getInstance(ClearPassword.ALGORITHM_CLEAR);
                        Password pass = factory.generatePassword(new ClearPasswordSpec(password.toCharArray()));
                        ((CredentialCallback) callback).setCredential(new PasswordCredential(pass));
                    } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                        throw new IllegalStateException(e);
                    }
                } else if (callback instanceof EvidenceVerifyCallback) {
                    PasswordGuessEvidence evidence = (PasswordGuessEvidence) ((EvidenceVerifyCallback) callback).getEvidence();
                    ((EvidenceVerifyCallback) callback).setVerified(Arrays.equals(evidence.getGuess(), password.toCharArray()));
                } else if (callback instanceof AuthenticationCompleteCallback) {
                    // NO-OP
                } else if (callback instanceof IdentityCredentialCallback) {
                    // NO-OP
                } else if (callback instanceof AuthorizeCallback) {
                    if(username.equals(((AuthorizeCallback) callback).getAuthenticationID()) &&
                       username.equals(((AuthorizeCallback) callback).getAuthorizationID())) {
                        ((AuthorizeCallback) callback).setAuthorized(true);
                    } else {
                        ((AuthorizeCallback) callback).setAuthorized(false);
                    }
                } else {
                    throw new UnsupportedCallbackException(callback);
                }
            }
        };
    }

    public class TestingHttpExchangeSpi implements HttpExchangeSpi {

        private List<String> requestAuthorizationHeaders = Collections.emptyList();
        private List<String> responseAuthenticateHeaders = new LinkedList<>();
        private List<String> responseAuthenticationInfoHeaders = new LinkedList<>();
        private int statusCode;
        private Status result;

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
            this.requestAuthorizationHeaders = requestAuthorizationHeaders;
        }

        // ------

        public List<String> getRequestHeaderValues(String headerName) {
            if (AUTHORIZATION.equals(headerName)) {
                return requestAuthorizationHeaders;
            } else {
                throw new IllegalStateException();
            }
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
            return "GET";
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
