/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016 Red Hat, Inc., and individual contributors
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

import java.io.IOException;
import java.util.Objects;
import java.util.Set;

import org.wildfly.security.auth.client.AuthenticationConfiguration.CredentialSetting;
import org.wildfly.security.credential.AlgorithmCredential;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.source.CredentialSource;
import org.wildfly.security.sasl.util.SaslMechanismInformation;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
class SetCredentialsConfiguration extends AuthenticationConfiguration implements CredentialSetting {

    private final CredentialSource credentialSource;

    SetCredentialsConfiguration(final AuthenticationConfiguration parent, final CredentialSource credentialSource) {
        super(parent.without(CredentialSetting.class, SetCallbackHandlerAuthenticationConfiguration.class));
        this.credentialSource = credentialSource;
    }

    boolean saslSupportedByConfiguration(final String mechanismName) {
        Set<Class<? extends Credential>> types = SaslMechanismInformation.getSupportedClientCredentialTypes(mechanismName);
        final CredentialSource credentials = credentialSource;
        for (Class<? extends Credential> type : types) {
            if (AlgorithmCredential.class.isAssignableFrom(type)) {
                Set<String> algorithms = SaslMechanismInformation.getSupportedClientCredentialAlgorithms(mechanismName, type);
                if (algorithms.contains("*")) {
                    try {
                        if (credentials.getCredentialAcquireSupport(type, null).mayBeSupported()) {
                            return true;
                        }
                    } catch (IOException e) {
                        // no match
                    }
                } else {
                    for (String algorithm : algorithms) {
                        try {
                            if (credentials.getCredentialAcquireSupport(type, algorithm).mayBeSupported()) {
                                return true;
                            }
                        } catch (IOException e) {
                            // no match
                        }
                    }
                }
            } else {
                try {
                    if (credentials.getCredentialAcquireSupport(type).mayBeSupported()) {
                        return true;
                    }
                } catch (IOException e) {
                    // no match
                }
            }
        }
        return super.saslSupportedByConfiguration(mechanismName);
    }

    @Override
    CredentialSource getCredentialSource() {
        return credentialSource;
    }

    AuthenticationConfiguration reparent(final AuthenticationConfiguration newParent) {
        return new SetCredentialsConfiguration(newParent, credentialSource);
    }

    boolean halfEqual(final AuthenticationConfiguration other) {
        return Objects.equals(other.getCredentialSource(), credentialSource) && parentHalfEqual(other);
    }

    int calcHashCode() {
        return multiHashUnordered(parentHashCode(), 2693, Objects.hashCode(credentialSource));
    }

    @Override
    StringBuilder asString(StringBuilder sb) {
        return parentAsString(sb).append("Credentials,");
    }


}
