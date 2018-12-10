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

package org.wildfly.security.ssl;

import java.net.Socket;
import java.security.Principal;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;

import org.wildfly.common.Assert;
import org.wildfly.security._private.ElytronMessages;
import org.wildfly.security.auth.server.MechanismConfigurationSelector;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.auth.server.ServerAuthenticationContext;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.credential.X509CertificateChainCredential;
import org.wildfly.security.evidence.X509PeerCertificateChainEvidence;
import org.wildfly.security.x500.util.X500PrincipalUtil;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
class SecurityDomainTrustManager extends X509ExtendedTrustManager {

    private final X509ExtendedTrustManager delegate;
    private final SecurityDomain securityDomain;
    private final boolean authenticationOptional;
    private final MechanismConfigurationSelector mechanismConfigurationSelector;

    SecurityDomainTrustManager(final X509ExtendedTrustManager delegate, final SecurityDomain securityDomain, final boolean authenticationOptional, final MechanismConfigurationSelector mechanismConfigurationSelector) {
        this.delegate = delegate;
        this.securityDomain = securityDomain;
        this.authenticationOptional = authenticationOptional;
        this.mechanismConfigurationSelector = mechanismConfigurationSelector;
    }

    SecurityDomainTrustManager(final X509TrustManager delegate, final SecurityDomain securityDomain, final boolean authenticationOptional, final MechanismConfigurationSelector mechanismConfigurationSelector) {
        this(delegate instanceof X509ExtendedTrustManager ?
                (X509ExtendedTrustManager) delegate :
                new WrappingX509ExtendedTrustManager(delegate), securityDomain, authenticationOptional, mechanismConfigurationSelector);
    }

    public void checkClientTrusted(final X509Certificate[] chain, final String authType, final Socket socket) throws CertificateException {
        delegate.checkClientTrusted(chain, authType, socket);
        doClientTrustCheck(chain, authType, ((SSLSocket) socket).getHandshakeSession());
    }

    public void checkClientTrusted(final X509Certificate[] chain, final String authType, final SSLEngine sslEngine) throws CertificateException {
        delegate.checkClientTrusted(chain, authType, sslEngine);
        doClientTrustCheck(chain, authType, sslEngine.getHandshakeSession());
    }

    public void checkClientTrusted(final X509Certificate[] chain, final String authType) throws CertificateException {
        delegate.checkClientTrusted(chain, authType);
        doClientTrustCheck(chain, authType, null);
    }

    private void doClientTrustCheck(final X509Certificate[] chain, final String authType, final SSLSession handshakeSession) throws CertificateException {
        Assert.checkNotNullParam("chain", chain);
        Assert.checkNotNullParam("authType", authType);
        if (chain.length == 0) {
            throw ElytronMessages.log.emptyChainNotTrusted();
        }
        Principal principal = X500PrincipalUtil.asX500Principal(chain[0].getSubjectX500Principal());
        if (principal == null) {
            throw ElytronMessages.log.notTrusted(null);
        }
        try (final ServerAuthenticationContext authenticationContext = securityDomain.createNewAuthenticationContext(mechanismConfigurationSelector)) {
            authenticationContext.setAuthenticationPrincipal(principal);
            if (! authenticationContext.exists()) {
                if (authenticationOptional) {
                    ElytronMessages.log.tracef("Credential validation failed: no identity found for principal [%s], ignoring as authentication is optional", principal);
                    return;
                } else {
                    throw ElytronMessages.log.notTrusted(principal);
                }
            }
            if (authenticationContext.getCredentialAcquireSupport(X509CertificateChainCredential.class).mayBeSupported()) {
                X509CertificateChainCredential credential = authenticationContext.getCredential(X509CertificateChainCredential.class);
                if (credential == null) {
                    if (authenticationOptional) {
                        ElytronMessages.log.tracef("Credential validation failed: no trusted certificate found for principal [%s], ignoring as authentication is optional", principal);
                        return;
                    } else {
                        throw ElytronMessages.log.notTrusted(principal);
                    }
                }
                if (! credential.getFirstCertificate().equals(chain[0])) {
                    if (authenticationOptional) {
                        ElytronMessages.log.tracef("Credential validation failed: certificate does not match for principal [%s], ignoring as authentication is optional", principal);
                        return;
                    } else {
                        throw ElytronMessages.log.notTrusted(principal);
                    }
                }
            } else if (authenticationContext.getEvidenceVerifySupport(X509PeerCertificateChainEvidence.class).mayBeSupported()) {
                final X509PeerCertificateChainEvidence evidence = new X509PeerCertificateChainEvidence(chain);
                if (! authenticationContext.verifyEvidence(evidence)) {
                    if (authenticationOptional) {
                        ElytronMessages.log.tracef("Credential validation failed: no trusted certificate found for principal [%s], ignoring as authentication is optional", principal);
                        return;
                    } else {
                        throw ElytronMessages.log.notTrusted(principal);
                    }
                }
            }
            if (! authenticationContext.authorize()) {
                if (authenticationOptional) {
                    ElytronMessages.log.tracef("Credential validation failed: identity is not authorized principal [%s], ignoring as authentication is optional", principal);
                    return;
                } else {
                    throw ElytronMessages.log.notTrusted(principal);
                }
            }
            ElytronMessages.log.tracef("Authentication succeed for principal [%s]", principal);
            authenticationContext.succeed();
            if (handshakeSession != null) {
                handshakeSession.putValue(SSLUtils.SSL_SESSION_IDENTITY_KEY, authenticationContext.getAuthorizedIdentity());
            }
        } catch (RealmUnavailableException e) {
            throw ElytronMessages.log.notTrustedRealmProblem(e, principal);
        }
    }

    public void checkServerTrusted(final X509Certificate[] chain, final String authType, final Socket socket) throws CertificateException {
        delegate.checkServerTrusted(chain, authType, socket);
    }

    public void checkServerTrusted(final X509Certificate[] chain, final String authType, final SSLEngine sslEngine) throws CertificateException {
        delegate.checkServerTrusted(chain, authType, sslEngine);
    }

    public void checkServerTrusted(final X509Certificate[] chain, final String authType) throws CertificateException {
        delegate.checkServerTrusted(chain, authType);
    }

    public X509Certificate[] getAcceptedIssuers() {
        return delegate.getAcceptedIssuers();
    }
}
