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

import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.concurrent.ThreadLocalRandom;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.security.auth.x500.X500Principal;

import org.wildfly.security.credential.X509CertificateChainPrivateCredential;
import org.wildfly.security.x500.util.X500PrincipalUtil;

final class ConfigurationKeyManager extends X509ExtendedKeyManager {
    private final Map<String, Map<X500Principal, String>> credentialAliasesByKeyTypeAndIssuer;
    private final Map<String, X509CertificateChainPrivateCredential> credentialsByAlias;

    ConfigurationKeyManager(final Map<String, Map<X500Principal, String>> credentialAliasesByKeyTypeAndIssuer, final Map<String, X509CertificateChainPrivateCredential> credentialsByAlias) {
        this.credentialAliasesByKeyTypeAndIssuer = credentialAliasesByKeyTypeAndIssuer;
        this.credentialsByAlias = credentialsByAlias;
    }

    private String getCredentialAlias(final String keyType, final Principal[] issuers) {
        final Map<X500Principal, String> aliasesByIssuer = credentialAliasesByKeyTypeAndIssuer.get(keyType);
        if (aliasesByIssuer != null) {
            if (issuers != null) {
                for (Principal issuer : issuers) {
                    X500Principal x500Principal = X500PrincipalUtil.asX500Principal(issuer);
                    if (x500Principal != null) {
                        final String alias = aliasesByIssuer.get(x500Principal);
                        if (alias != null) {
                            return alias;
                        }
                    }
                }
            } else {
                Iterator<String> iterator = aliasesByIssuer.values().iterator();
                if (iterator.hasNext()) {
                    return iterator.next();
                }
            }
        }
        return null;
    }

    public String[] getClientAliases(final String keyType, final Principal[] issuers) {
        final Map<X500Principal, String> aliasesByIssuer = credentialAliasesByKeyTypeAndIssuer.get(keyType);
        LinkedHashSet<String> aliases = null;
        if (aliasesByIssuer != null) {
            if (issuers != null) {
                for (Principal issuer : issuers) {
                    X500Principal x500Principal = X500PrincipalUtil.asX500Principal(issuer);
                    if (x500Principal != null) {
                        final String alias = aliasesByIssuer.get(x500Principal);
                        if (alias != null) {
                            if (aliases == null) aliases = new LinkedHashSet<>(3);
                            aliases.add(alias);
                        }
                    }
                }
            } else {
                for (final String alias : aliasesByIssuer.values()) {
                    if (alias != null) {
                        if (aliases == null) aliases = new LinkedHashSet<>(3);
                        aliases.add(alias);
                    }
                }
            }
        }
        return aliases == null ? null : aliases.toArray(new String[aliases.size()]);
    }

    public String chooseClientAlias(final String[] keyTypes, final Principal[] issuers, final Socket socket) {
        for (String keyType : keyTypes) {
            final String alias = getCredentialAlias(keyType, issuers);
            if (alias != null) {
                return alias;
            }
        }
        return null;
    }

    public String chooseEngineClientAlias(final String[] keyTypes, final Principal[] issuers, final SSLEngine sslEngine) {
        for (String keyType : keyTypes) {
            final String alias = getCredentialAlias(keyType, issuers);
            if (alias != null) {
                return alias;
            }
        }
        return null;
    }

    public String[] getServerAliases(final String keyType, final Principal[] issuers) {
        throw new UnsupportedOperationException();
    }

    public String chooseServerAlias(final String keyType, final Principal[] issuers, final Socket socket) {
        throw new UnsupportedOperationException();
    }

    public String chooseEngineServerAlias(final String KeyType, final Principal[] issuers, final SSLEngine sslEngine) {
        throw new UnsupportedOperationException();
    }

    public X509Certificate[] getCertificateChain(final String alias) {
        final X509CertificateChainPrivateCredential credential = credentialsByAlias.get(alias);
        return credential == null ? null : credential.getCertificateChain();
    }

    public PrivateKey getPrivateKey(final String alias) {
        final X509CertificateChainPrivateCredential credential = credentialsByAlias.get(alias);
        return credential == null ? null : credential.getPrivateKey();
    }

    /**
     * Obtain a new {@link Builder} capable of building a {@link ConfigurationKeyManager}.
     *
     * @return a new {@link Builder} capable of building a {@link ConfigurationKeyManager}.
     */
    public static Builder builder() {
        return new Builder();
    }

    static final class Builder {
        private final Map<String, Map<X500Principal, String>> credentialAliasesByKeyTypeAndIssuer = new HashMap<>();
        private final Map<String, X509CertificateChainPrivateCredential> credentialsByAlias = new HashMap<>();

        Builder() {
        }

        void addCredential(X509CertificateChainPrivateCredential credential) {
            final PrivateKey privateKey = credential.getPrivateKey();
            final X509Certificate[] certificateChain = credential.getCertificateChain();
            final String keyType = privateKey.getAlgorithm();
            String alias;
            do {
                alias = randomString();
            } while (credentialsByAlias.containsKey(alias));
            credentialsByAlias.put(alias, credential);
            Map<X500Principal, String> aliasesByIssuer = credentialAliasesByKeyTypeAndIssuer.get(keyType);
            if (aliasesByIssuer == null) {
                credentialAliasesByKeyTypeAndIssuer.put(keyType, aliasesByIssuer = new HashMap<>(1));
            }
            for (X509Certificate certificate : certificateChain) {
                final X500Principal principal = certificate.getIssuerX500Principal();
                aliasesByIssuer.put(principal, alias);
            }
        }

        private String randomString() {
            char[] c = new char[12];
            int r;
            final ThreadLocalRandom random = ThreadLocalRandom.current();
            for (int i = 0; i < c.length; i ++) {
                r = random.nextInt() & 0x3f;
                c[i] = (char) (r < 26 ? 'A' + r : r < 52 ? 'a' + r - 26 : r == 62 ? '+' : '_');
            }
            return new String(c);
        }

        ConfigurationKeyManager build() {
            return new ConfigurationKeyManager(credentialAliasesByKeyTypeAndIssuer, credentialsByAlias);
        }
    }
}
