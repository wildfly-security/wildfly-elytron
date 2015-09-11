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

package org.wildfly.security.sasl.util;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.Map;

import javax.net.ssl.X509KeyManager;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;

import org.wildfly.common.Assert;
import org.wildfly.security.FixedSecurityFactory;
import org.wildfly.security.SecurityFactory;
import org.wildfly.security.auth.callback.CredentialCallback;
import org.wildfly.security.x500.X509CertificateChainPrivateCredential;

/**
 * A {@link SaslServerFactory} which sets the server's credential using the given key manager.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public final class KeyManagerCredentialSaslServerFactory extends AbstractDelegatingSaslServerFactory {

    private final SecurityFactory<X509KeyManager> keyManagerFactory;

    /**
     * Construct a new instance.
     *
     * @param delegate the delegate SASL server factory
     * @param keyManager the key manager to use (must not be {@code null})
     */
    public KeyManagerCredentialSaslServerFactory(final SaslServerFactory delegate, final X509KeyManager keyManager) {
        super(delegate);
        Assert.checkNotNullParam("keyManager", keyManager);
        this.keyManagerFactory = new FixedSecurityFactory<>(keyManager);

    }

    public SaslServer createSaslServer(final String mechanism, final String protocol, final String serverName, final Map<String, ?> props, final CallbackHandler cbh) throws SaslException {
        return delegate.createSaslServer(mechanism, protocol, serverName, props, callbacks -> {
            ArrayList<Callback> list = new ArrayList<>(Arrays.asList(callbacks));
            final Iterator<Callback> iterator = list.iterator();
            while (iterator.hasNext()) {
                Callback callback = iterator.next();
                if (callback instanceof CredentialCallback) {
                    X509KeyManager keyManager = null;
                    try {
                        keyManager = keyManagerFactory.create();
                    } catch (GeneralSecurityException e) {
                        throw new SaslException(e.getMessage(), e);
                    }
                    final CredentialCallback credentialCallback = (CredentialCallback) callback;
                    out:
                    {
                        for (Class<?> allowedType : credentialCallback.getAllowedTypes()) {
                            for (String algorithmName : credentialCallback.getAllowedAlgorithms(allowedType)) {
                                final String alias = keyManager.chooseServerAlias(algorithmName, null, null);
                                if (alias != null) {
                                    final X509Certificate[] certificateChain = keyManager.getCertificateChain(alias);
                                    final PrivateKey privateKey = keyManager.getPrivateKey(alias);
                                    if (certificateChain == null || certificateChain.length == 0) {
                                        credentialCallback.setCredential(privateKey);
                                        iterator.remove();
                                        break out;
                                    } else {
                                        credentialCallback.setCredential(new X509CertificateChainPrivateCredential(privateKey, certificateChain));
                                        iterator.remove();
                                        break out;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            if (! list.isEmpty()) {
                cbh.handle(list.toArray(new Callback[list.size()]));
            }
        });
    }
}
