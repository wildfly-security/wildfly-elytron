/*
 * JBoss, Home of Professional Open Source
 * Copyright 2021 Red Hat, Inc., and individual contributors
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
package org.wildfly.security.auth.realm;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.Provider;
import java.util.function.Supplier;

import javax.crypto.SecretKey;

import org.wildfly.common.Assert;
import org.wildfly.security.auth.server.NameRewriter;
import org.wildfly.security.password.spec.Encoding;


/**
 * A builder class that creates {@link FileSystemSecurityRealm} instances.
 *
 * @author <a href="mailto:araskar@redhat.com">Ashpan Raskar</a>
 */
public class FileSystemSecurityRealmBuilder {

    private Path root;
    private NameRewriter nameRewriter;
    private int levels = 2;
    private boolean encoded = true;
    private Charset hashCharset;
    private Encoding hashEncoding;
    private SecretKey secretKey;
    private Supplier<Provider[]> providers;

    FileSystemSecurityRealmBuilder() {
    }

    /**
     * Set the root path to be used by the realm.
     *
     * @param root the root path of the identity store (must not be {@code null})
     * @return this builder.enc
     */
    public FileSystemSecurityRealmBuilder setRoot(final Path root) {
        Assert.checkNotNullParam("root", root);
        this.root = root;
        return this;
    }

    /**
     * Set the name rewriter to be used by the realm.
     *
     * @param nameRewriter the name rewriter to apply to looked up names (must not be {@code null})
     * @return this builder.
     */
    public FileSystemSecurityRealmBuilder setNameRewriter(final NameRewriter nameRewriter) {
        Assert.checkNotNullParam("nameRewriter", nameRewriter);
        this.nameRewriter = nameRewriter;
        return this;
    }

    /**
     * Set the number of levels to be used by the realm.
     *
     * @param levels the number of levels of directory hashing to apply
     * @return this builder.
     */
    public FileSystemSecurityRealmBuilder setLevels(final int levels) {
        this.levels = levels;
        return this;
    }

    /**
     * Set whether the identity name should be encoded for the filename in the realm.
     *
     * @param encoded whether identity names should be BASE32 encoded before using as filename (only applies if the security realm is unencrypted)
     * @return this builder.
     */
    public FileSystemSecurityRealmBuilder setEncoded(final boolean encoded) {
        this.encoded = encoded;
        return this;
    }

    /**
     * Set the character set to be used by the realm.
     *
     * @param hashCharset the character set to use when converting password strings to a byte array. Uses UTF-8 by default. (must not be {@code null})
     * @return this builder.
     */
    public FileSystemSecurityRealmBuilder setHashCharset(final Charset hashCharset) {
        Assert.checkNotNullParam("hashCharset", hashCharset);
        this.hashCharset = hashCharset;
        return this;
    }

    /**
     * Set the string format for hashed passwords to be used by the realm.
     *
     * @param hashEncoding the string format for the hashed passwords. Uses Base64 by default. (must not be {@code null})
     * @return this builder.
     */
    public FileSystemSecurityRealmBuilder setHashEncoding(final Encoding hashEncoding) {
        Assert.checkNotNullParam("hashEncoding", hashEncoding);
        this.hashEncoding = hashEncoding;
        return this;
    }

    /**
     * Set the SecretKey to be used by the realm.
     *
     * @param secretKey the symmetric SecretKey used to encrypt and decrypt the Security Realm (must not be {@code null})
     * @return this builder.
     */
    public FileSystemSecurityRealmBuilder setSecretKey(final SecretKey secretKey) {
        Assert.checkNotNullParam("secretKey", secretKey);
        this.secretKey = secretKey;
        return this;
    }

    public FileSystemSecurityRealmBuilder setProviders(final Supplier<Provider[]> providers) {
        Assert.checkNotNullParam("providers", providers);
        this.providers = providers;
        return this;
    }

    /**
     * Builds a new {@link FileSystemSecurityRealm} instance based on configuration defined for this {@link FileSystemSecurityRealmBuilder} instance.
     *
     * @return the built realm
     */
    public FileSystemSecurityRealm build() {
        encoded = secretKey == null && encoded;
        if (nameRewriter == null) {
            nameRewriter = NameRewriter.IDENTITY_REWRITER;
        }
        if (hashEncoding == null) {
            hashEncoding = Encoding.BASE64;
        }
        if (hashCharset == null) {
            hashCharset = StandardCharsets.UTF_8;
        }
        return new FileSystemSecurityRealm(root, nameRewriter, levels, encoded, hashEncoding, hashCharset, providers, secretKey);
    }
}
