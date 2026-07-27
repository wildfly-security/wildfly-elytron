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
package org.wildfly.security.http.cert;

import static org.wildfly.security.http.HttpConstants.CLIENT_CERT_NAME;
import static org.wildfly.security.mechanism._private.ElytronMessages.httpClientCert;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.BooleanSupplier;
import java.util.function.Function;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.wildfly.security.auth.callback.AuthenticationCompleteCallback;
import org.wildfly.security.auth.callback.CachedIdentityAuthorizeCallback;
import org.wildfly.security.auth.callback.EvidenceDecodePrincipalCallback;
import org.wildfly.security.auth.callback.EvidenceVerifyCallback;
import org.wildfly.security.auth.callback.PrincipalAuthorizeCallback;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.auth.server.SecurityIdentity;
import org.wildfly.security.cache.CachedIdentity;
import org.wildfly.security.cache.IdentityCache;
import org.wildfly.security.evidence.X509PeerCertificateChainEvidence;
import org.wildfly.security.http.HttpAuthenticationException;
import org.wildfly.security.http.HttpScope;
import org.wildfly.security.http.HttpServerAuthenticationMechanism;
import org.wildfly.security.http.HttpServerRequest;
import org.wildfly.security.http.Scope;
import org.wildfly.security.mechanism.AuthenticationMechanismException;
import org.wildfly.security.mechanism._private.MechanismUtil;
import org.wildfly.security.x500.X500;

/**
 * The CLIENT_CERT authentication mechanism.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
final class ClientCertAuthenticationMechanism implements HttpServerAuthenticationMechanism {

    private static final String IDENTITY_CACHE_KEY = "org.wildfly.elytron.identity-cache";

    private final CallbackHandler callbackHandler;
    private final boolean skipVerification;

    /**
     * Construct a new instance of the {@code ClientCertAuthenticationMechanism} mechanism.
     *
     * @param callbackHandler the {@link CallbackHandler} to use to verify the supplied credentials and to notify to establish the current identity.
     * @param skipVerification whether the certificate verification using {@link EvidenceVerifyCallback} should be skipped
     */
    ClientCertAuthenticationMechanism(CallbackHandler callbackHandler, boolean skipVerification) {
        this.callbackHandler = callbackHandler;
        this.skipVerification = skipVerification;
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
        Certificate[] rawCerts = request.getPeerCertificates();
        if (rawCerts == null) {
            httpClientCert.trace("Peer Unverified");
            request.noAuthenticationInProgress();
            return;
        }

        final X509Certificate[] peerCertificates = X500.asX509CertificateArray(rawCerts);

        Function<SecurityDomain, IdentityCache> cacheFunction = createIdentityCacheFunction(request, peerCertificates);

        if (cacheFunction != null && attemptReAuthentication(request, cacheFunction)) {
            httpClientCert.trace("Re-authentication succeed");
            return;
        }
        if (attemptAuthentication(request, peerCertificates, cacheFunction)) {
            return;
        }
        httpClientCert.trace("Both, re-authentication and authentication, failed");
        fail(request);
    }

    private boolean attemptAuthentication(HttpServerRequest request, X509Certificate[] peerCertificates, Function<SecurityDomain, IdentityCache> cacheFunction) throws HttpAuthenticationException {
        X509PeerCertificateChainEvidence evidence = new X509PeerCertificateChainEvidence(peerCertificates);

        if (httpClientCert.isTraceEnabled()) {
            httpClientCert.tracef("Authenticating using following certificates: [%s]", Arrays.toString(peerCertificates));
        }

        EvidenceVerifyCallback callback = new EvidenceVerifyCallback(evidence);

            try {
                if (! skipVerification) {
                    MechanismUtil.handleCallbacks(httpClientCert, callbackHandler, callback);
                } else {
                    // Since handling of EvidenceVerifyCallback is being skipped here, ensure evidence
                    // decoding still takes place
                    EvidenceDecodePrincipalCallback evidenceDecodePrincipalCallback = new EvidenceDecodePrincipalCallback(evidence);
                    MechanismUtil.handleCallbacks(httpClientCert, callbackHandler, evidenceDecodePrincipalCallback);
                }
            } catch (AuthenticationMechanismException e) {
                throw e.toHttpAuthenticationException();
            } catch (UnsupportedCallbackException e) {
                throw httpClientCert.mechCallbackHandlerFailedForUnknownReason(e).toHttpAuthenticationException();
            }

        boolean verified = callback.isVerified();
        httpClientCert.tracef("X509PeerCertificateChainEvidence was verified by EvidenceVerifyCallback handler: %b  verification skipped: %b", verified, skipVerification);

        if (verified || skipVerification) {
            final BooleanSupplier authorizedFunction;
            final Callback authorizeCallBack;
            if (cacheFunction != null) {
                CachedIdentityAuthorizeCallback cacheCallback = new CachedIdentityAuthorizeCallback(evidence.getDecodedPrincipal(), cacheFunction, true);
                authorizedFunction = cacheCallback::isAuthorized;
                authorizeCallBack = cacheCallback;
            } else {
                PrincipalAuthorizeCallback principalCallback = new PrincipalAuthorizeCallback(evidence.getDecodedPrincipal());
                authorizedFunction = principalCallback::isAuthorized;
                authorizeCallBack = principalCallback;
            }

            try {
                MechanismUtil.handleCallbacks(httpClientCert, callbackHandler, authorizeCallBack);
            } catch (AuthenticationMechanismException e) {
                throw e.toHttpAuthenticationException();
            } catch (UnsupportedCallbackException e) {
                throw httpClientCert.mechCallbackHandlerFailedForUnknownReason(e).toHttpAuthenticationException();
            }

            boolean authorized = authorizedFunction.getAsBoolean();
            httpClientCert.tracef("X509PeerCertificateChainEvidence was authorized by CachedIdentityAuthorizeCallback(%s) handler: %b", evidence.getDecodedPrincipal(), authorized);
            if (authorized && succeed(request)) {
                httpClientCert.trace("Authentication succeed");
                return true;
            }
        }
        return false;
    }

    private boolean succeed(HttpServerRequest request) throws HttpAuthenticationException {
        try {
            MechanismUtil.handleCallbacks(httpClientCert, callbackHandler, AuthenticationCompleteCallback.SUCCEEDED);
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
            MechanismUtil.handleCallbacks(httpClientCert, callbackHandler, AuthenticationCompleteCallback.FAILED);
            request.authenticationFailed(httpClientCert.authenticationFailed());
        } catch (AuthenticationMechanismException e) {
            throw e.toHttpAuthenticationException();
        } catch (UnsupportedCallbackException ignored) {
            // ignored
        }
    }

    private boolean attemptReAuthentication(HttpServerRequest request, Function<SecurityDomain, IdentityCache> cacheFunction) throws HttpAuthenticationException {
        CachedIdentityAuthorizeCallback authorizeCallback = new CachedIdentityAuthorizeCallback(cacheFunction, true);
        try {
            MechanismUtil.handleCallbacks(httpClientCert, callbackHandler, authorizeCallback);
        } catch (AuthenticationMechanismException e) {
            throw e.toHttpAuthenticationException();
        } catch (UnsupportedCallbackException e) {
            throw httpClientCert.mechCallbackHandlerFailedForUnknownReason(e).toHttpAuthenticationException();
        }
        boolean authorized = authorizeCallback.isAuthorized();
        httpClientCert.tracef("Identity was authorized by CachedIdentityAuthorizeCallback handler: %b", authorized);
        if (authorized) {
            return succeed(request);
        }
        return false;
    }

    private Function<SecurityDomain, IdentityCache> createIdentityCacheFunction(HttpServerRequest request, X509Certificate[] peerCertificates) {
        final HttpScope sslSessionScope = resolveScope(request, Scope.SSL_SESSION);
        final HttpScope connectionScope = resolveScope(request, Scope.CONNECTION);

        if ((sslSessionScope == null || !sslSessionScope.exists()) &&
            (connectionScope == null || !connectionScope.exists())) {
            return null;
        }

        return securityDomain -> new IdentityCache() {

            @Override
            public void put(SecurityIdentity identity) {
                if (securityDomain == null) {
                    return;
                }
                Function<X509Certificate[], CachedIdentity> entry =
                        createCacheEntry(new CachedIdentity(CLIENT_CERT_NAME, false, identity), peerCertificates);
                httpClientCert.tracef("storing into cache: %s", identity);
                // Overwrite (not putIfAbsent): a fresh authentication always supersedes a stale entry.
                if (sslSessionScope != null && sslSessionScope.exists()) {
                    entryMap(sslSessionScope).put(securityDomain, entry);
                }
                if (connectionScope != null && connectionScope.exists()) {
                    entryMap(connectionScope).put(securityDomain, entry);
                }
            }

            @Override
            public CachedIdentity get() {
                if (securityDomain == null) {
                    return null;
                }
                if (sslSessionScope != null && sslSessionScope.exists()) {
                    CachedIdentity cached = getCachedOrEvict(sslSessionScope, peerCertificates);
                    if (cached != null) {
                        httpClientCert.tracef("loading from SSL_SESSION cache: %s", cached);
                        return cached;
                    }
                }
                if (connectionScope != null && connectionScope.exists()) {
                    CachedIdentity cached = getCachedOrEvict(connectionScope, peerCertificates);
                    if (cached != null) {
                        httpClientCert.tracef("loading from CONNECTION cache: %s", cached);
                        return cached;
                    }
                }
                httpClientCert.tracef("loading from cache: null");
                return null;
            }

            @Override
            public CachedIdentity remove() {
                if (securityDomain == null) {
                    return null;
                }
                httpClientCert.tracef("clearing identity cache");
                removeFromScope(sslSessionScope);
                removeFromScope(connectionScope);
                // The lambda returned by createCacheEntry is opaque after creation — the stored
                // identity cannot be extracted back. Callers universally discard remove()'s return
                // value across the codebase, so returning null is safe.
                return null;
            }

            @SuppressWarnings("unchecked")
            private CachedIdentity getCachedOrEvict(HttpScope scope, X509Certificate[] currentCerts) {
                Map<SecurityDomain, Function<X509Certificate[], CachedIdentity>> map =
                        (Map<SecurityDomain, Function<X509Certificate[], CachedIdentity>>) scope.getAttachment(IDENTITY_CACHE_KEY);
                if (map == null) {
                    return null;
                }
                Function<X509Certificate[], CachedIdentity> entry = map.get(securityDomain);
                if (entry == null) {
                    return null;
                }
                CachedIdentity cached = entry.apply(currentCerts);
                if (cached == null) {
                    // Cert chain changed — evict stale entry so a subsequent put() stores a fresh one.
                    map.remove(securityDomain);
                }
                return cached;
            }

            @SuppressWarnings("unchecked")
            private void removeFromScope(HttpScope scope) {
                if (scope == null || !scope.exists()) {
                    return;
                }
                Map<SecurityDomain, ?> map =
                        (Map<SecurityDomain, ?>) scope.getAttachment(IDENTITY_CACHE_KEY);
                if (map != null) {
                    map.remove(securityDomain);
                }
            }
        };
    }

    /**
     * Returns a cache entry function that yields the given identity only when applied to the
     * same certificate chain that was used to authenticate it. This ensures a scope cache entry
     * cannot be reused by a different peer (e.g. after TLS 1.2 renegotiation with different
     * client credentials). Applying this check uniformly across all scopes — including
     * SSL_SESSION — keeps the logic consistent and safe for future scope additions.
     */
    private static Function<X509Certificate[], CachedIdentity> createCacheEntry(
            CachedIdentity identity, X509Certificate[] certChain) {
        final List<X509Certificate> storedChain = Collections.unmodifiableList(Arrays.asList(certChain.clone()));
        return presentedCerts -> Arrays.asList(presentedCerts).equals(storedChain) ? identity : null;
    }

    private static HttpScope resolveScope(HttpServerRequest request, Scope scope) {
        HttpScope httpScope = request.getScope(scope);
        return (httpScope != null && httpScope.supportsAttachments()) ? httpScope : null;
    }

    private static Map<SecurityDomain, Function<X509Certificate[], CachedIdentity>> entryMap(HttpScope scope) {
        return MechanismUtil.computeIfAbsent(scope, IDENTITY_CACHE_KEY, key -> new ConcurrentHashMap<>());
    }
}
