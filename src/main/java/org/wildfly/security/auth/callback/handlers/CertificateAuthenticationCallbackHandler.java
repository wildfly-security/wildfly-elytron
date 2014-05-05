/*
 * JBoss, Home of Professional Open Source
 * Copyright 2013 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.auth.callback.handlers;

import java.io.IOException;
import org.wildfly.security.auth.callback.ExtendedCallback;

import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.x500.X500Principal;

public final class CertificateAuthenticationCallbackHandler implements CallbackHandler {
    private final X500Principal principal;
    private final X509KeyManager keyManager;
    private final X509TrustManager trustManager;

    public CertificateAuthenticationCallbackHandler(final X500Principal principal, final X509KeyManager keyManager, final X509TrustManager trustManager) {
        this.principal = principal;
        this.keyManager = keyManager;
        this.trustManager = trustManager;
    }

    public void handle(final Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        for (Callback callback : callbacks) {
            keyManager.getClientAliases(keyType, principal);
            keyManager.getPrivateKey(alias);
            trustManager.checkServerTrusted();
            if (callback instanceof ExtendedCallback && ((ExtendedCallback) callback).isOptional()) {
                continue;
            }
            throw new UnsupportedCallbackException(callback);
        }
    }
}
