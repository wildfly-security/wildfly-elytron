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

package org.wildfly.security.sasl.entity;

import static org.wildfly.security.sasl.entity.EntityUtil.isCertChainTrusted;

import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;

import org.wildfly.security.auth.callback.CredentialCallback;
import org.wildfly.security.auth.callback.TrustedAuthoritiesCallback;
import org.wildfly.security.auth.callback.VerifyPeerTrustedCallback;
import org.wildfly.security.sasl.util.AbstractDelegatingSaslServerFactory;

/**
 * A {@link SaslServerFactory} which can be configured with the necessary information for entity auth.
 *
 * @author Kabir Khan
 */
public final class ConfiguredEntitySaslServerFactory extends AbstractDelegatingSaslServerFactory {
    private final List<TrustedAuthority> trustedAuthorities;
    private final KeyStore trustStore;
    private final KeyStore keyStore;
    private final String keyStoreAlias;
    private final char[] keyStorePassword;

    /**
     * Construct a new instance.
     * @param delegate the delegate SASL server factory
     * @param trustedAuthorities the trusted authorities
     * @param trustStore the trust store
     * @param keyStore the key store
     * @param keyStoreAlias the key store alias
     * @param keyStorePassword the key store password
     */
    public ConfiguredEntitySaslServerFactory(final SaslServerFactory delegate, List<TrustedAuthority> trustedAuthorities,
                                             KeyStore trustStore, KeyStore keyStore, String keyStoreAlias, char[] keyStorePassword) {
        super(delegate);
        this.trustedAuthorities = trustedAuthorities;
        this.trustStore = trustStore;
        this.keyStore = keyStore;
        this.keyStoreAlias = keyStoreAlias;
        this.keyStorePassword = keyStorePassword;
    }

    public SaslServer createSaslServer(final String mechanism, final String protocol, final String serverName, final Map<String, ?> props, final CallbackHandler cbh) throws SaslException {
        return delegate.createSaslServer(mechanism, protocol, serverName, props, callbacks -> {
            ArrayList<Callback> list = new ArrayList<>(Arrays.asList(callbacks));
            final Iterator<Callback> iterator = list.iterator();
            while (iterator.hasNext()) {
                Callback callback = iterator.next();
                try {
                    boolean handled = true;
                    if (callback instanceof VerifyPeerTrustedCallback) {
                        final VerifyPeerTrustedCallback verifyTrustedCallback = (VerifyPeerTrustedCallback) callback;
                        verifyTrustedCallback.setVerified(isCertChainTrusted(trustStore, verifyTrustedCallback.getCertificateChain()));
                    } else if (callback instanceof TrustedAuthoritiesCallback) {
                        ((TrustedAuthoritiesCallback) callback).setTrustedAuthorities(trustedAuthorities);
                    } else if (callback instanceof CredentialCallback) {
                        final CredentialCallback credentialCallback = (CredentialCallback) callback;
                        for (Class<?> allowedType : credentialCallback.getAllowedTypes()) {
                            if (allowedType == X509Certificate[].class) {
                                Certificate[] certChain;
                                certChain = keyStore.getCertificateChain(keyStoreAlias);
                                credentialCallback.setCredential(Arrays.copyOf(certChain, certChain.length, X509Certificate[].class));
                                break;
                            } else if (allowedType == PrivateKey.class) {
                                credentialCallback.setCredential(keyStore.getKey(keyStoreAlias, keyStorePassword));
                                break;
                            }
                        }
                    } else {
                        handled = false;
                    }
                    if (handled) {
                        iterator.remove();
                    }
                } catch (GeneralSecurityException e) {
                    SaslException ex = new SaslException(e.getLocalizedMessage());
                    ex.initCause(e);
                    throw ex;
                }
            }
            if (!list.isEmpty()) {
                cbh.handle(list.toArray(new Callback[list.size()]));
            }
        });
    }


}
