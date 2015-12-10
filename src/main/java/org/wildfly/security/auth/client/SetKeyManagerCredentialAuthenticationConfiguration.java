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

package org.wildfly.security.auth.client;

import static org.wildfly.security._private.ElytronMessages.log;
import static org.wildfly.security.sasl.entity.TrustedAuthority.CertificateTrustedAuthority;
import static org.wildfly.security.sasl.entity.TrustedAuthority.NameTrustedAuthority;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.net.ssl.X509KeyManager;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.x500.X500Principal;

import org.wildfly.security.SecurityFactory;
import org.wildfly.security.auth.callback.CredentialCallback;
import org.wildfly.security.auth.callback.TrustedAuthoritiesCallback;
import org.wildfly.security.sasl.entity.TrustedAuthority;
import org.wildfly.security.credential.X509CertificateChainPrivateCredential;
import org.wildfly.security.sasl.util.SaslMechanismInformation;

/**
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
class SetKeyManagerCredentialAuthenticationConfiguration extends AuthenticationConfiguration {

    private final SecurityFactory<X509KeyManager> keyManagerFactory;

    SetKeyManagerCredentialAuthenticationConfiguration(final AuthenticationConfiguration parent, final SecurityFactory<X509KeyManager> keyManagerFactory) {
        super(parent.without(SetPasswordAuthenticationConfiguration.class).without(SetCallbackHandlerAuthenticationConfiguration.class).without(SetGSSCredentialAuthenticationConfiguration.class).without(SetKeyStoreCredentialAuthenticationConfiguration.class).without(SetCertificateCredentialAuthenticationConfiguration.class));
        this.keyManagerFactory = keyManagerFactory;
    }

    AuthenticationConfiguration reparent(final AuthenticationConfiguration newParent) {
        return new SetKeyManagerCredentialAuthenticationConfiguration(newParent, keyManagerFactory);
    }

    SecurityFactory<X509KeyManager> getX509KeyManagerFactory() throws GeneralSecurityException {
        return keyManagerFactory;
    }

    void handleCallbacks(final AuthenticationConfiguration config, final Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        List<TrustedAuthority> trustedAuthorities = null;
        for (Callback callback : callbacks) {
            if (callback instanceof TrustedAuthoritiesCallback) {
                trustedAuthorities = ((TrustedAuthoritiesCallback) callback).getTrustedAuthorities();
            } else if (callback instanceof CredentialCallback) {
                final X509KeyManager keyManager;
                try {
                    keyManager = keyManagerFactory.create();
                } catch (GeneralSecurityException e) {
                    throw log.unableToCreateKeyManager(e);
                }
                final CredentialCallback credentialCallback = (CredentialCallback) callback;
                final String allowedAlgorithm = credentialCallback.getAlgorithm();
                if (allowedAlgorithm != null) {
                    if (credentialCallback.isCredentialTypeSupported(X509CertificateChainPrivateCredential.class, allowedAlgorithm)) {
                        final String alias = keyManager.chooseClientAlias(new String[] { allowedAlgorithm }, getAcceptableIssuers(trustedAuthorities), null);
                        if (alias != null) {
                            final X509Certificate[] certificateChain = keyManager.getCertificateChain(alias);
                            final PrivateKey privateKey = keyManager.getPrivateKey(alias);
                            credentialCallback.setCredential(new X509CertificateChainPrivateCredential(privateKey, certificateChain));
                        }
                    }
                }
            }
        }
        super.handleCallbacks(config, callbacks);
    }

    void handleCallback(final Callback[] callbacks, final int index) throws IOException, UnsupportedCallbackException {
        final Callback callback = callbacks[index];
        if (callback instanceof TrustedAuthoritiesCallback || callback instanceof CredentialCallback) {
            return;
        }
        super.handleCallback(callbacks, index);
    }

    boolean filterOneSaslMechanism(final String mechanismName) {
        // just add entity methods; don't try and narrow down the algorithm type
        return SaslMechanismInformation.IEC_ISO_9798.test(mechanismName) || super.filterOneSaslMechanism(mechanismName);
    }

    private Principal[] getAcceptableIssuers(List<TrustedAuthority> trustedAuthorities) {
        if (trustedAuthorities == null) {
            return null;
        }
        List<Principal> issuers = new ArrayList<Principal>();
        for (TrustedAuthority trustedAuthority : trustedAuthorities) {
            if (trustedAuthority instanceof TrustedAuthority.CertificateTrustedAuthority) {
                final X509Certificate authorityCertificate = ((CertificateTrustedAuthority) trustedAuthority).getIdentifier();
                issuers.add(authorityCertificate.getSubjectX500Principal());
            } else if (trustedAuthority instanceof NameTrustedAuthority) {
                final String authorityName = ((NameTrustedAuthority) trustedAuthority).getIdentifier();
                issuers.add(new X500Principal(authorityName));
            }
        }
        return issuers.toArray(new Principal[issuers.size()]);
    }
}
