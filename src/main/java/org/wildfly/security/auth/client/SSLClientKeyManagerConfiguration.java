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

import java.security.GeneralSecurityException;

import javax.net.ssl.X509KeyManager;

import org.wildfly.security.SecurityFactory;
import org.wildfly.security.auth.client.AuthenticationConfiguration.SSLCredentialSetting;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
class SSLClientKeyManagerConfiguration extends AuthenticationConfiguration implements SSLCredentialSetting {

    private final SecurityFactory<X509KeyManager> keyManagerFactory;

    SSLClientKeyManagerConfiguration(final AuthenticationConfiguration parent, final SecurityFactory<X509KeyManager> keyManagerFactory) {
        super(parent.without(SSLCredentialSetting.class));
        this.keyManagerFactory = keyManagerFactory;
    }

    AuthenticationConfiguration reparent(final AuthenticationConfiguration newParent) {
        return new SSLClientKeyManagerConfiguration(newParent, keyManagerFactory);
    }

    SecurityFactory<X509KeyManager> getX509KeyManagerFactory() throws GeneralSecurityException {
        return keyManagerFactory;
    }
}
