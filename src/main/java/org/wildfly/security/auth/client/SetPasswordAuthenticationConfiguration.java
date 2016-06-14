/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2014 Red Hat, Inc., and individual contributors
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
import java.util.Map;
import java.util.Set;
import java.util.function.Predicate;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.Sasl;

import org.wildfly.security.auth.callback.CredentialCallback;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.TwoWayPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.sasl.util.SaslMechanismInformation;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
class SetPasswordAuthenticationConfiguration extends AuthenticationConfiguration {

    private static final Predicate<String> ALWAYS_MATCH_PREDICATE = (prompt) -> true;
    private final Password password;
    private final Predicate<String> matchPredicate;

    SetPasswordAuthenticationConfiguration(final AuthenticationConfiguration parent, final Password password, final Predicate<String> matchPredicate) {
        super(parent.without(SetCallbackHandlerAuthenticationConfiguration.class).without(SetKeyStoreCredentialAuthenticationConfiguration.class).without(SetAnonymousAuthenticationConfiguration.class).without(SetGSSCredentialAuthenticationConfiguration.class).without(SetKeyManagerCredentialAuthenticationConfiguration.class).without(SetCertificateCredentialAuthenticationConfiguration.class), matchPredicate != null);
        this.password = password;
        this.matchPredicate = matchPredicate == null ? ALWAYS_MATCH_PREDICATE : matchPredicate;
    }

    void handleCallback(final Callback[] callbacks, final int index) throws IOException, UnsupportedCallbackException {
        Callback callback = callbacks[index];
        if (callback instanceof CredentialCallback) {
            CredentialCallback credentialCallback = (CredentialCallback) callback;
            if (credentialCallback.isCredentialTypeSupported(PasswordCredential.class, password.getAlgorithm())) {
                credentialCallback.setCredential(new PasswordCredential(password));
                return;
            }
        } else if (callback instanceof PasswordCallback) {
            PasswordCallback passwordCallback = (PasswordCallback) callback;
            if (matchPredicate.test(passwordCallback.getPrompt())) {
                if (password instanceof TwoWayPassword) try {
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

    void configureSaslProperties(final Map<String, Object> properties) {
        properties.put(Sasl.CREDENTIALS, password);
        super.configureSaslProperties(properties);
    }

    boolean filterOneSaslMechanism(final String mechanismName) {
        String passwordAlgorithm = password.getAlgorithm();
        Set<Class<? extends Credential>> types = SaslMechanismInformation.getSupportedClientCredentialTypes(mechanismName);
        Set<String> algorithms = SaslMechanismInformation.getSupportedClientCredentialAlgorithms(mechanismName, PasswordCredential.class);
        return (types == null || types.contains(PasswordCredential.class)) && (algorithms.isEmpty() || algorithms.contains(passwordAlgorithm)) || super.filterOneSaslMechanism(mechanismName);
    }

    AuthenticationConfiguration reparent(final AuthenticationConfiguration newParent) {
        return new SetPasswordAuthenticationConfiguration(newParent, password, matchPredicate);
    }
}
