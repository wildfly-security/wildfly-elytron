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
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.x500.X500Principal;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslClientFactory;
import javax.security.sasl.SaslException;

import org.wildfly.security._private.ElytronMessages;
import org.wildfly.security.auth.callback.CredentialCallback;
import org.wildfly.security.auth.callback.TrustedAuthoritiesCallback;
import org.wildfly.security.auth.callback.VerifyPeerTrustedCallback;
import org.wildfly.security.sasl.util.AbstractDelegatingSaslClientFactory;

/**
 * A {@link SaslClientFactory} which can be configured with the necessary information for entity auth.
 *
 * @author Kabir Khan
 */
public final class ConfiguredEntitySaslClientFactory extends AbstractDelegatingSaslClientFactory {
    private final KeyStore keyStore;
    private final KeyStore trustStore;
    private final String keyStoreAlias;
    private final char[] keyStorePassword;

    /**
     * Construct a new instance.
     * @param delegate the delegate SASL server factory
     * @param trustStore the trust store
     * @param keyStore the key store
     * @param keyStoreAlias the key store alias. If the server responds with a list of trusted authorities, this will be ignored.
     * @param keyStorePassword the key store password
     */
        public ConfiguredEntitySaslClientFactory(final SaslClientFactory delegate,
                                             KeyStore trustStore, KeyStore keyStore, String keyStoreAlias, char[] keyStorePassword) {
        super(delegate);
        this.trustStore = trustStore;
        this.keyStore = keyStore;
        this.keyStoreAlias = keyStoreAlias;
        this.keyStorePassword = keyStorePassword;
    }

    @Override
    public SaslClient createSaslClient(String[] mechanisms, String authorizationId, String protocol, String serverName, Map<String, ?> props, CallbackHandler cbh) throws SaslException {
        return super.createSaslClient(mechanisms, authorizationId, protocol, serverName, props, callbacks -> {

            List<TrustedAuthority> trustedAuthorities = null;
            String privateKeyAlias = keyStoreAlias;

            ArrayList<Callback> list = new ArrayList<>(Arrays.asList(callbacks));
            final Iterator<Callback> iterator = list.iterator();
            while (iterator.hasNext()) {
                Callback callback = iterator.next();

                try {
                    boolean handled = true;
                    if (callback instanceof TrustedAuthoritiesCallback) {
                        trustedAuthorities = ((TrustedAuthoritiesCallback) callback).getTrustedAuthorities();
                    } else if (callback instanceof CredentialCallback) {
                        final CredentialCallback credentialCallback = (CredentialCallback) callback;
                        for (Class<?> allowedType : credentialCallback.getAllowedTypes()) {
                            if (allowedType == X509Certificate[].class) {
                                Certificate[] certChain = null;
                                if (trustedAuthorities != null) {
                                    boolean compliantCertFound = false;
                                    List<String> aliases = Collections.list(keyStore.aliases());
                                    out: {
                                        for (String alias : aliases) {
                                            if (keyStore.entryInstanceOf(alias, KeyStore.PrivateKeyEntry.class)) {
                                                certChain = keyStore.getCertificateChain(alias);
                                                for (Certificate cert : certChain) {
                                                    X500Principal principal = ((X509Certificate) cert).getSubjectX500Principal();
                                                    for (TrustedAuthority trustedAuthority : trustedAuthorities) {
                                                        if (trustedAuthority instanceof TrustedAuthority.NameTrustedAuthority) {
                                                            String authorityName = ((TrustedAuthority.NameTrustedAuthority) trustedAuthority).getIdentifier();
                                                            if (principal.equals(new X500Principal(authorityName))) {
                                                                compliantCertFound = true;
                                                                privateKeyAlias = alias;
                                                                break out;
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    if (! compliantCertFound) {
                                        throw ElytronMessages.log.noCompliantCertificateFound();
                                    }
                                } else {
                                    certChain = keyStore.getCertificateChain(keyStoreAlias);
                                }
                                credentialCallback.setCredential(Arrays.copyOf(certChain, certChain.length, X509Certificate[].class));
                                break;
                            } else if (allowedType == PrivateKey.class) {
                                credentialCallback.setCredential(keyStore.getKey(privateKeyAlias, keyStorePassword));
                                break;
                            }
                        }
                    } else if (callback instanceof VerifyPeerTrustedCallback) {
                        final VerifyPeerTrustedCallback verifyTrustedCallback = (VerifyPeerTrustedCallback) callback;
                        verifyTrustedCallback.setVerified(isCertChainTrusted(trustStore, verifyTrustedCallback.getCertificateChain()));
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
