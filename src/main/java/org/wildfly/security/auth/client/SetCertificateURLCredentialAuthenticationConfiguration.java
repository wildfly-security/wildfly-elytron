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

import java.io.IOException;
import java.net.URL;
import java.security.PrivateKey;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.wildfly.common.Assert;
import org.wildfly.security.auth.callback.CredentialCallback;

/**
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
class SetCertificateURLCredentialAuthenticationConfiguration extends AuthenticationConfiguration {

    private final PrivateKey privateKey;
    private final URL certificateUrl;

    SetCertificateURLCredentialAuthenticationConfiguration(final AuthenticationConfiguration parent, final PrivateKey privateKey, final URL certificateUrl) {
        super(parent.without(SetPasswordAuthenticationConfiguration.class).without(SetCallbackHandlerAuthenticationConfiguration.class).without(SetGSSCredentialAuthenticationConfiguration.class).without(SetKeyStoreCredentialAuthenticationConfiguration.class).without(SetKeyManagerCredentialAuthenticationConfiguration.class).without(SetCertificateCredentialAuthenticationConfiguration.class));
        Assert.checkNotNullParam("privateKey", privateKey);
        Assert.checkNotNullParam("certificateUrl", certificateUrl);
        this.privateKey = privateKey;
        this.certificateUrl = certificateUrl;
    }

    AuthenticationConfiguration reparent(final AuthenticationConfiguration newParent) {
        return new SetCertificateURLCredentialAuthenticationConfiguration(newParent, privateKey, certificateUrl);
    }

    void handleCallback(final Callback[] callbacks, final int index) throws IOException, UnsupportedCallbackException {
        final Callback callback = callbacks[index];
        if (callback instanceof CredentialCallback) {
            final CredentialCallback credentialCallback = (CredentialCallback) callback;
            if (credentialCallback.isCredentialSupported(certificateUrl.getClass(), null)) {
                credentialCallback.setCredential(certificateUrl);
                return;
            } else if (credentialCallback.isCredentialSupported(privateKey.getClass(), privateKey.getAlgorithm())) {
                credentialCallback.setCredential(privateKey);
                return;
            }
        }
        super.handleCallback(callbacks, index);
    }
}
