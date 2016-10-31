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

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Set;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.wildfly.security.SecurityFactory;
import org.wildfly.security.auth.callback.CredentialCallback;
import org.wildfly.security.auth.client.AuthenticationConfiguration.CredentialSetting;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.X509CertificateChainPrivateCredential;
import org.wildfly.security.sasl.util.SaslMechanismInformation;

/**
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
class SetCertificateCredentialAuthenticationConfiguration extends AuthenticationConfiguration implements CredentialSetting {

    private final SecurityFactory<X509CertificateChainPrivateCredential> credentialFactory;

    SetCertificateCredentialAuthenticationConfiguration(final AuthenticationConfiguration parent, final SecurityFactory<X509CertificateChainPrivateCredential> credentialFactory) {
        super(parent.without(CredentialSetting.class));
        this.credentialFactory = credentialFactory;
    }

    AuthenticationConfiguration reparent(final AuthenticationConfiguration newParent) {
        return new SetCertificateCredentialAuthenticationConfiguration(newParent, credentialFactory);
    }

    void handleCallback(final Callback[] callbacks, final int index) throws IOException, UnsupportedCallbackException {
        final Callback callback = callbacks[index];
        if (callback instanceof CredentialCallback) {
            final CredentialCallback credentialCallback = (CredentialCallback) callback;
            final X509CertificateChainPrivateCredential certChainPrivateCredential;
            try {
                certChainPrivateCredential = credentialFactory.create();
            } catch (GeneralSecurityException e) {
                throw log.unableToReadCredential(e);
            }
            if (credentialCallback.isCredentialSupported(certChainPrivateCredential)) {
                credentialCallback.setCredential(certChainPrivateCredential);
                return;
            }
        }
        super.handleCallback(callbacks, index);
    }

    boolean filterOneSaslMechanism(final String mechanismName) {
        Set<Class<? extends Credential>> types = SaslMechanismInformation.getSupportedClientCredentialTypes(mechanismName);
        return types == null || types.contains(X509CertificateChainPrivateCredential.class) || super.filterOneSaslMechanism(mechanismName);
    }
}
