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
package org.wildfly.security.http.impl;

import static org.wildfly.security._private.ElytronMessages.log;
import static org.wildfly.security.http.HttpConstants.CLIENT_CERT_NAME;

import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.wildfly.security.auth.callback.AuthenticationCompleteCallback;
import org.wildfly.security.auth.callback.CachedIdentityAuthorizeCallback;
import org.wildfly.security.auth.callback.EvidenceVerifyCallback;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.auth.server.SecurityIdentity;
import org.wildfly.security.cache.CachedIdentity;
import org.wildfly.security.cache.IdentityCache;
import org.wildfly.security.evidence.X509PeerCertificateChainEvidence;
import org.wildfly.security.http.HttpAuthenticationException;
import org.wildfly.security.http.HttpServerAuthenticationMechanism;
import org.wildfly.security.http.HttpServerRequest;
import org.wildfly.security.mechanism.AuthenticationMechanismException;
import org.wildfly.security.mechanism.MechanismUtil;
import org.wildfly.security.ssl.SSLUtils;
import org.wildfly.security.x500.X500;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;

/**
 * The CLIENT_CERT authentication mechanism.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class ClientCertAuthenticationMechanism implements HttpServerAuthenticationMechanism {

    private final CallbackHandler callbackHandler;

    /**
     * Construct a new instance of the {@code ClientCertAuthenticationMechanism} mechanism.
     *
     * @param callbackHandler the {@link CallbackHandler} to use to verify the supplied credentials and to notify to establish the current identity.
     */
    ClientCertAuthenticationMechanism(CallbackHandler callbackHandler) {
        this.callbackHandler = callbackHandler;
    }

    /**
     * @see org.wildfly.security.http.HttpServerAuthenticationMechanism#getMechanismName()
     */
    @Override
    public String getMechanismName() {
        return CLIENT_CERT_NAME;
    }

    /**
     * @see org.wildfly.security.http.HttpServerAuthenticationMechanism#evaluateRequest(org.wildfly.security.http.HttpServerRequest)
     */
    @Override
    public void evaluateRequest(HttpServerRequest request) throws HttpAuthenticationException {
        SSLSession sslSession = request.getSSLSession();
        if (sslSession == null) {
            request.noAuthenticationInProgress();
            return;
        }
        if (attemptReAuthentication(request)) {
            log.trace("ClientCertAuthenticationMechanism: re-authentication succeed");
            return;
        }
        if (attemptAuthentication(request, sslSession)) {
            log.trace("ClientCertAuthenticationMechanism: authentication succeed");
            return;
        }
        log.trace("ClientCertAuthenticationMechanism: both, re-authentication and authentication, failed");
        fail(request);
    }

    private boolean attemptAuthentication(HttpServerRequest request, SSLSession sslSession) throws HttpAuthenticationException {
        X509Certificate[] x509Certificates = null;
        try {
            x509Certificates = X500.asX509CertificateArray(sslSession.getPeerCertificates());
        } catch (SSLPeerUnverifiedException e) {
            if(request.isAuthenticationRequired()) {
                Certificate[] certs = request.renegotiateForClientCertAuth();
                if(certs != null) {
                    x509Certificates = X500.asX509CertificateArray(certs);
                }
            }
            if(x509Certificates == null) {
                log.trace("CLIENT-CERT Peer Unverified");
                request.noAuthenticationInProgress();
                return true;
            }
        }
        X509PeerCertificateChainEvidence evidence = new X509PeerCertificateChainEvidence(x509Certificates);

        log.tracef("Using ClientCertAuthenticationMechanism to authenticate the following certificates: [%s]", x509Certificates);

        EvidenceVerifyCallback callback = new EvidenceVerifyCallback(evidence);
        try {
            MechanismUtil.handleCallbacks(CLIENT_CERT_NAME, callbackHandler, callback);
        } catch (AuthenticationMechanismException e) {
            throw e.toHttpAuthenticationException();
        } catch (UnsupportedCallbackException e) {
            throw log.mechCallbackHandlerFailedForUnknownReason(CLIENT_CERT_NAME, e).toHttpAuthenticationException();
        }
        boolean verified = callback.isVerified();
        log.tracef("X509PeerCertificateChainEvidence was verified by EvidenceVerifyCallback handler: %b", verified);
        if (verified) {
            CachedIdentityAuthorizeCallback authorizeCallback = new CachedIdentityAuthorizeCallback(evidence.getPrincipal(), createIdentityCache(request), true);
            try {
                MechanismUtil.handleCallbacks(CLIENT_CERT_NAME, callbackHandler, authorizeCallback);
            } catch (AuthenticationMechanismException e) {
                throw e.toHttpAuthenticationException();
            } catch (UnsupportedCallbackException e) {
                throw log.mechCallbackHandlerFailedForUnknownReason(CLIENT_CERT_NAME, e).toHttpAuthenticationException();
            }

            boolean authorized = authorizeCallback.isAuthorized();
            log.tracef("X509PeerCertificateChainEvidence was authorized by CachedIdentityAuthorizeCallback(%s) handler: %b", evidence.getPrincipal(), authorized);
            if (authorized) if (succeed(request)) return true;
        }
        return false;
    }

    private boolean succeed(HttpServerRequest request) throws HttpAuthenticationException {
        try {
            MechanismUtil.handleCallbacks(CLIENT_CERT_NAME, callbackHandler, AuthenticationCompleteCallback.SUCCEEDED);
            request.authenticationComplete();
            return true;
        } catch (AuthenticationMechanismException e) {
            throw e.toHttpAuthenticationException();
        } catch (UnsupportedCallbackException ignored) {
            // ignored
        }
        return false;
    }

    private void fail(HttpServerRequest request) throws HttpAuthenticationException {
        try {
            MechanismUtil.handleCallbacks(CLIENT_CERT_NAME, callbackHandler, AuthenticationCompleteCallback.FAILED);
            request.authenticationFailed(log.authenticationFailed(CLIENT_CERT_NAME));
        } catch (AuthenticationMechanismException e) {
            throw e.toHttpAuthenticationException();
        } catch (UnsupportedCallbackException ignored) {
            // ignored
        }
    }

    private boolean attemptReAuthentication(HttpServerRequest request) throws HttpAuthenticationException {
        CachedIdentityAuthorizeCallback authorizeCallback = new CachedIdentityAuthorizeCallback(createIdentityCache(request), true);
        try {
            MechanismUtil.handleCallbacks(CLIENT_CERT_NAME, callbackHandler, authorizeCallback);
        } catch (AuthenticationMechanismException e) {
            throw e.toHttpAuthenticationException();
        } catch (UnsupportedCallbackException e) {
            throw log.mechCallbackHandlerFailedForUnknownReason(CLIENT_CERT_NAME, e).toHttpAuthenticationException();
        }
        boolean authorized = authorizeCallback.isAuthorized();
        log.tracef("Identity was authorized by CachedIdentityAuthorizeCallback handler: %b", authorized);
        if (authorized) {
            return succeed(request);
        }
        return false;
    }

    private Function<SecurityDomain, IdentityCache> createIdentityCache(HttpServerRequest request) {
        SSLSession sslSession = request.getSSLSession();
        if (sslSession == null) {
            return null;
        }
        return securityDomain -> new IdentityCache() {

            final Map<SecurityDomain, CachedIdentity> identities = SSLUtils.computeIfAbsent(sslSession, "org.wildfly.elytron.identity-cache", key -> new ConcurrentHashMap<>());

            @Override
            public void put(SecurityIdentity identity) {
                identities.putIfAbsent(securityDomain, new CachedIdentity(getMechanismName(), identity));
            }

            @Override
            public CachedIdentity get() {
                return identities.get(securityDomain);
            }

            @Override
            public CachedIdentity remove() {
                return identities.remove(securityDomain);
            }
        };
    }
}
