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

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Set;
import java.util.function.Function;
import java.util.function.Supplier;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.wildfly.security.auth.callback.CredentialCallback;
import org.wildfly.security.auth.client.AuthenticationConfiguration.CredentialSetting;
import org.wildfly.security.auth.server.IdentityCredentials;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.TwoWayPassword;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.sasl.util.SaslMechanismInformation;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
class SetCredentialsConfiguration extends AuthenticationConfiguration implements CredentialSetting {

    private final Function<String, IdentityCredentials> credentialsFunction;

    SetCredentialsConfiguration(final AuthenticationConfiguration parent, final Function<String, IdentityCredentials> credentialsFunction) {
        super(parent.without(CredentialSetting.class));
        this.credentialsFunction = credentialsFunction;
    }

    SetCredentialsConfiguration(final AuthenticationConfiguration parent, final Supplier<IdentityCredentials> credentials) {
        this(parent, prompt -> credentials.get());
    }

    void handleCallback(final Callback[] callbacks, final int index) throws UnsupportedCallbackException, IOException {
        Callback callback = callbacks[index];
        if (callback instanceof CredentialCallback) {
            final CredentialCallback credentialCallback = (CredentialCallback) callback;
            final Credential credential = credentialsFunction.apply(null).getCredential(credentialCallback.getCredentialType(), credentialCallback.getAlgorithm());
            if (credential != null && credentialCallback.isCredentialSupported(credential)) {
                credentialCallback.setCredential(credential);
                return;
            }
        } else if (callback instanceof PasswordCallback) {
            final PasswordCallback passwordCallback = (PasswordCallback) callback;
            IdentityCredentials credentials = credentialsFunction.apply(passwordCallback.getPrompt());
            if (credentials != null) {
                final TwoWayPassword password = credentials.applyToCredential(PasswordCredential.class, ClearPassword.ALGORITHM_CLEAR, c -> c.getPassword(TwoWayPassword.class));
                if (password instanceof ClearPassword) {
                    // shortcut
                    passwordCallback.setPassword(((ClearPassword) password).getPassword());
                    return;
                } else if (password != null) try {
                    PasswordFactory passwordFactory = PasswordFactory.getInstance(password.getAlgorithm());
                    ClearPasswordSpec clearPasswordSpec = passwordFactory.getKeySpec(passwordFactory.translate(password), ClearPasswordSpec.class);
                    passwordCallback.setPassword(clearPasswordSpec.getEncodedPassword());
                    return;
                } catch (GeneralSecurityException e) {
                    // fall out
                }
            }
        }
        super.handleCallback(callbacks, index);
    }

    boolean filterOneSaslMechanism(final String mechanismName) {
        Set<Class<? extends Credential>> types = SaslMechanismInformation.getSupportedClientCredentialTypes(mechanismName);
        final IdentityCredentials credentials = credentialsFunction.apply(null);
        for (Class<? extends Credential> type : types) {
            Set<String> algorithms = SaslMechanismInformation.getSupportedClientCredentialAlgorithms(mechanismName, type);
            if (algorithms.contains("*")) {
                if (credentials.contains(type, null)) {
                    return true;
                }
            } else {
                for (String algorithm : algorithms) {
                    if (credentials.contains(type, algorithm)) {
                        return true;
                    }
                }
            }
        }
        return super.filterOneSaslMechanism(mechanismName);
    }

    Function<String, IdentityCredentials> getCredentialsFunction() {
        return credentialsFunction;
    }

    AuthenticationConfiguration reparent(final AuthenticationConfiguration newParent) {
        return new SetCredentialsConfiguration(newParent, credentialsFunction);
    }

    @Override
    StringBuilder asString(StringBuilder sb) {
        return parentAsString(sb).append("Credentials,");
    }


}
