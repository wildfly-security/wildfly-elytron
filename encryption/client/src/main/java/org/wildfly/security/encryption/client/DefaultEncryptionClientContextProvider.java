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

import static java.security.AccessController.doPrivileged;

import java.security.PrivilegedAction;

/**
 * A lazily-initialized holder for the default encrypted expression context.
 * If an error occurs setting up the default encryption client
 * context, the empty context is used.
 *
 * @author <a href="mailto:prpaul@redhat.com">Prarthona Paul</a>
 */
class DefaultEncryptionClientContextProvider {

    static final EncryptionClientContext DEFAULT;

    static {
        DEFAULT = doPrivileged((PrivilegedAction<EncryptionClientContext>) () -> {
            try {
                return EncryptionClientXmlParser.parseEncryptionClientConfiguration().create();
            } catch (Throwable t) {
                throw new InvalidEncryptionClientConfigurationException(t);
            }
        });
    }
}
