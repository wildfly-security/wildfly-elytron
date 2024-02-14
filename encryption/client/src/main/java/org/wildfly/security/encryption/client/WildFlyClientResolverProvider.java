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

import org.kohsuke.MetaInfServices;
import org.wildfly.client.config.ResolverProvider;

/**
 * Implementation of the ResolverProvider interface that allows another project
 * to use Functions from Encrypted Expression Resolver without adding an
 * Elytron dependency.
 * @author <a href="mailto:prpaul@redhat.com">Prarthona Paul</a>
 */

@MetaInfServices(value = ResolverProvider.class)
public class WildFlyClientResolverProvider implements ResolverProvider{

    @Override
    public String resolveExpression(String expression) {
        EncryptionClientContext context = EncryptionClientContext.captureCurrent();
        if (context.encryptionClientConfiguration != null) {
            return context.encryptionClientConfiguration.encryptedExpressionResolver.resolveExpression(expression, context.encryptionClientConfiguration);
        } else {
            throw new EncryptedExpressionResolutionException("Encryption client configuration could not be found.");
        }
    }
}
