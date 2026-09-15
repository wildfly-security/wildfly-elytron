/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2026 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.keystore;

import static org.wildfly.common.Assert.checkNotNullParam;

import java.nio.file.Path;
import java.security.KeyStore;

/**
 * Load parameters for a PEM {@link KeyStore} backed by separate certificate and private key files.  The certificate
 * file contains the leaf certificate followed by any issuer certificates in chain order.  The private key file
 * contains one unencrypted private key.  The paths are read when the KeyStore is loaded, not when this parameter is
 * constructed.
 */
public final class PemKeyStoreLoadParameter implements KeyStore.LoadStoreParameter {

    private final Path certificatePath;
    private final Path privateKeyPath;
    private final String alias;
    private final KeyStore.ProtectionParameter protectionParameter;

    /**
     * Construct a new instance using the default {@code tls} alias and no key password.
     *
     * @param certificatePath the PEM certificate path (must not be {@code null})
     * @param privateKeyPath the PEM private key path (must not be {@code null})
     * @throws IllegalArgumentException if either path is {@code null}
     */
    public PemKeyStoreLoadParameter(Path certificatePath, Path privateKeyPath) {
        this(certificatePath, privateKeyPath, null, null);
    }

    /**
     * Construct a new instance using no key password.
     *
     * @param certificatePath the PEM certificate path (must not be {@code null})
     * @param privateKeyPath the PEM private key path (must not be {@code null})
     * @param alias the key entry alias, or {@code null} to use {@code tls}
     * @throws IllegalArgumentException if either path is {@code null}
     */
    public PemKeyStoreLoadParameter(Path certificatePath, Path privateKeyPath, String alias) {
        this(certificatePath, privateKeyPath, alias, null);
    }

    /**
     * Construct a new instance.
     *
     * @param certificatePath the PEM certificate path (must not be {@code null})
     * @param privateKeyPath the PEM private key path (must not be {@code null})
     * @param alias the key entry alias, or {@code null} to use {@code tls}
     * @param protectionParameter a {@link KeyStore.PasswordProtection}, or {@code null} for an empty key password
     * @throws IllegalArgumentException if either path is {@code null}
     */
    public PemKeyStoreLoadParameter(Path certificatePath, Path privateKeyPath, String alias, KeyStore.ProtectionParameter protectionParameter) {
        this.certificatePath = checkNotNullParam("certificatePath", certificatePath);
        this.privateKeyPath = checkNotNullParam("privateKeyPath", privateKeyPath);
        this.alias = alias == null ? PemKeyStoreUtil.DEFAULT_ALIAS : alias;
        this.protectionParameter = protectionParameter;
    }

    /**
     * Get the PEM certificate path.
     *
     * @return the PEM certificate path
     */
    public Path getCertificatePath() {
        return certificatePath;
    }

    /**
     * Get the PEM private key path.
     *
     * @return the PEM private key path
     */
    public Path getPrivateKeyPath() {
        return privateKeyPath;
    }

    /**
     * Get the key entry alias.
     *
     * @return the key entry alias (never {@code null})
     */
    public String getAlias() {
        return alias;
    }

    @Override
    public KeyStore.ProtectionParameter getProtectionParameter() {
        return protectionParameter;
    }
}
