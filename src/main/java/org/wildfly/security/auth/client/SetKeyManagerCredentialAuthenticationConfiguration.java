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

import static org.wildfly.common.math.HashMath.multiHashUnordered;

import java.util.Objects;

import javax.net.ssl.X509KeyManager;

import org.wildfly.security.SecurityFactory;
import org.wildfly.security.auth.client.AuthenticationConfiguration.CredentialSetting;
import org.wildfly.security.sasl.util.SaslMechanismInformation;

/**
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
class SetKeyManagerCredentialAuthenticationConfiguration extends AuthenticationConfiguration implements CredentialSetting {

    private final SecurityFactory<X509KeyManager> keyManagerFactory;

    SetKeyManagerCredentialAuthenticationConfiguration(final AuthenticationConfiguration parent, final SecurityFactory<X509KeyManager> keyManagerFactory) {
        super(parent.without(CredentialSetting.class, SetCallbackHandlerAuthenticationConfiguration.class));
        this.keyManagerFactory = keyManagerFactory;
    }

    AuthenticationConfiguration reparent(final AuthenticationConfiguration newParent) {
        return new SetKeyManagerCredentialAuthenticationConfiguration(newParent, keyManagerFactory);
    }

    SecurityFactory<X509KeyManager> getX509KeyManagerFactory() {
        return keyManagerFactory;
    }

    boolean saslSupportedByConfiguration(final String mechanismName) {
        // just add entity methods; don't try and narrow down the algorithm type
        return SaslMechanismInformation.IEC_ISO_9798.test(mechanismName) || super.filterOneSaslMechanism(mechanismName);
    }

    boolean halfEqual(final AuthenticationConfiguration other) {
        return Objects.equals(keyManagerFactory, other.getX509KeyManagerFactory()) && parentHalfEqual(other);
    }

    int calcHashCode() {
        return multiHashUnordered(parentHashCode(), 5309, Objects.hashCode(keyManagerFactory));
    }

    @Override
    StringBuilder asString(StringBuilder sb) {
        return parentAsString(sb).append("KeyManagerCredential,");
    }

}
