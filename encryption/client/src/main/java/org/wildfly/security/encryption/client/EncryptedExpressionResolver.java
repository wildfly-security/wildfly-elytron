/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2024 Red Hat, Inc., and individual contributors
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
package org.wildfly.security.encryption.client;

import org.wildfly.security.credential.SecretKeyCredential;
import org.wildfly.security.credential.store.CredentialStore;
import org.wildfly.security.credential.store.CredentialStoreException;
import org.wildfly.security.encryption.client._private.ElytronMessages;

import javax.crypto.SecretKey;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.Map;

import static org.wildfly.common.Assert.checkNotNullParam;
import static org.wildfly.security.encryption.CipherUtil.decrypt;
import static org.wildfly.security.encryption.CipherUtil.encrypt;

/**
 * A class used to resolve encrypted expressions using secret key within credential stores.
 * Contains a collection of multiple resolver configurations.
 *
 * @author <a href="mailto:prpaul@redhat.com">Prarthona Paul</a>
 */

public class EncryptedExpressionResolver {
    private volatile String prefix;
    private volatile String completePrefix;
    private volatile String defaultResolver;
    private volatile Map<String, ResolverConfiguration> resolverConfigurations;

    public EncryptedExpressionResolver() {
    }

    public String resolveExpression(String expression, EncryptionClientConfiguration config) {
        checkNotNullParam("expression", expression);
        checkNotNullParam("encrypted expression configuration", config);
        return resolveExpressionInternal(expression, config);
    }

    public Map<String, ResolverConfiguration> getResolverConfiguration() {
        return resolverConfigurations;
    }

    private String resolveExpressionInternal(String fullExpression, EncryptionClientConfiguration config) {
        assert config != null;

        if (fullExpression.length() > 3) {
            String expression = fullExpression.substring(2, fullExpression.length() - 1);

            if (completePrefix == null || completePrefix.isEmpty()) {
                throw ElytronMessages.xmlLog.expressionUnavailable();
            }
            else if (expression.startsWith(completePrefix)) {
                int delimiter = expression.indexOf(':', completePrefix.length());
                String resolver = delimiter > 0 ? expression.substring(completePrefix.length(), delimiter) : defaultResolver;
                if (resolver == null) {
                    throw ElytronMessages.xmlLog.expressionResolutionWithoutResolver(fullExpression);
                }

                ResolverConfiguration resolverConfiguration = resolverConfigurations.get(resolver);
                if (resolverConfiguration == null) {
                    throw ElytronMessages.xmlLog.invalidResolver(fullExpression);
                }

                ElytronMessages.xmlLog.tracef("Attempting to decrypt expression '%s' using credential store '%s' and alias '%s'.",
                        fullExpression, resolverConfiguration.credentialStore, resolverConfiguration.alias);
                CredentialStore credentialStore = config.getCredentialStoreMap().get(getResolverConfiguration().get(resolver).getCredentialStore());
                SecretKey secretKey;
                try {
                    SecretKeyCredential credential = credentialStore.retrieve(resolverConfiguration.getAlias(),
                            SecretKeyCredential.class);
                    secretKey = credential.getSecretKey();
                } catch (CredentialStoreException e) {
                    throw ElytronMessages.xmlLog.unableToLoadCredential(e);
                }

                String token = expression.substring(expression.lastIndexOf(':') + 1);

                try {
                    return decrypt(token, secretKey);
                } catch (GeneralSecurityException e) {
                    throw ElytronMessages.xmlLog.unableToDecryptExpression(fullExpression, e);
                }
            }
        }
        return null;
    }

    public String createExpression(final String clearText, EncryptionClientConfiguration config) {
        return createExpression(null, clearText, config);
    }

    public String createExpression(final String resolver, final String clearText, EncryptionClientConfiguration config) {
        String resolvedResolver = resolver != null ? resolver : defaultResolver;
        if (resolvedResolver == null) {
            throw ElytronMessages.xmlLog.noResolverSpecifiedAndNoDefault();
        }

        ResolverConfiguration resolverConfiguration = resolverConfigurations.get(resolvedResolver);
        if (resolverConfiguration == null) {
            throw ElytronMessages.xmlLog.noResolverWithSpecifiedName(resolvedResolver);
        }

        CredentialStore credentialStore = config.getCredentialStoreMap().get(getResolverConfiguration().get(resolvedResolver).getCredentialStore());
        SecretKey secretKey;
        try {
            SecretKeyCredential credential = credentialStore.retrieve(resolverConfiguration.getAlias(), SecretKeyCredential.class);
            if (credential == null) {
                throw ElytronMessages.xmlLog.credentialDoesNotExist(resolverConfiguration.getAlias(), SecretKeyCredential.class.getSimpleName());
            }
            secretKey = credential.getSecretKey();
        } catch (CredentialStoreException e) {
            throw ElytronMessages.xmlLog.unableToLoadCredential(e);
        }

        String cipherTextToken;
        try {
            cipherTextToken = encrypt(clearText, secretKey);
        } catch (GeneralSecurityException e) {
            throw ElytronMessages.xmlLog.unableToEncryptClearText(e);
        }

        String expression = resolver == null ? String.format("${%s::%s:%s}", prefix, defaultResolver, cipherTextToken)
                : String.format("${%s::%s:%s}", prefix, resolvedResolver, cipherTextToken);

        return expression;
    }

    public EncryptedExpressionResolver setPrefix(final String prefix) {
        this.prefix = prefix;
        this.completePrefix = prefix + "::";
        return this;
    }

    public EncryptedExpressionResolver setDefaultResolver(final String defaultResolver) {
        if (defaultResolver == null) {
            this.defaultResolver = getResolverConfiguration().entrySet().iterator().next().getKey();
        } else {
            this.defaultResolver = defaultResolver;
        }
        return this;
    }

    public EncryptedExpressionResolver setResolverConfigurations(final Map<String, ResolverConfiguration> resolverConfigurations) {
        this.resolverConfigurations = Collections.unmodifiableMap(resolverConfigurations);

        return this;
    }

    public static class ResolverConfiguration {

        private final String resolverName;
        private final String credentialStore;
        private final String alias;

        public ResolverConfiguration(final String resolverName, final String credentialStore, final String alias) {
            this.resolverName = checkNotNullParam("resolverName", resolverName);
            this.credentialStore = checkNotNullParam("credentialStore", credentialStore);
            this.alias = checkNotNullParam("alias", alias);
        }

        public String getCredentialStore() {
            return credentialStore;
        }

        public String getAlias() {
            return alias;
        }
    }
}
