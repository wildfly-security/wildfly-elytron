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
import java.util.function.Predicate;
import java.util.function.Supplier;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.wildfly.security.auth.callback.CredentialCallback;
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
class SetCredentialsConfiguration extends AuthenticationConfiguration {

    private static final Predicate<String> ALWAYS_MATCH_PREDICATE = prompt -> true;
    private final Supplier<IdentityCredentials> credentialsSupplier;
    private final Predicate<String> matchPredicate;

    SetCredentialsConfiguration(final AuthenticationConfiguration parent, final Supplier<IdentityCredentials> credentialsSupplier, final Predicate<String> matchPredicate) {
        super(parent.without(SetCallbackHandlerAuthenticationConfiguration.class).without(SetAnonymousAuthenticationConfiguration.class).without(SetPasswordCallbackHandlerAuthenticationConfiguration.class), matchPredicate != null);
        this.credentialsSupplier = credentialsSupplier;
        this.matchPredicate = matchPredicate == null ? ALWAYS_MATCH_PREDICATE : matchPredicate;
    }

    SetCredentialsConfiguration(final AuthenticationConfiguration parent, final Supplier<IdentityCredentials> credentialsSupplier) {
        this(parent, credentialsSupplier, ALWAYS_MATCH_PREDICATE);
    }

    void handleCallback(final Callback[] callbacks, final int index) throws UnsupportedCallbackException, IOException {
        Callback callback = callbacks[index];
        if (callback instanceof CredentialCallback) {
            final CredentialCallback credentialCallback = (CredentialCallback) callback;
            final Credential credential = credentialsSupplier.get().getCredential(credentialCallback.getCredentialType(), credentialCallback.getAlgorithm());
            if (credential != null && credentialCallback.isCredentialSupported(credential)) {
                credentialCallback.setCredential(credential);
                return;
            }
        } else if (callback instanceof PasswordCallback) {
            final PasswordCallback passwordCallback = (PasswordCallback) callback;
            if (matchPredicate.test(passwordCallback.getPrompt())) {
                final TwoWayPassword password = credentialsSupplier.get().applyToCredential(PasswordCredential.class, ClearPassword.ALGORITHM_CLEAR, c -> c.getPassword(TwoWayPassword.class));
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
        final IdentityCredentials credentials = credentialsSupplier.get();
        for (Class<? extends Credential> type : types) {
            Set<String> algorithms = SaslMechanismInformation.getSupportedClientCredentialAlgorithms(mechanismName, type);
            if (algorithms.contains("*")) {
                if (credentials.getCredentialAcquireSupport(type, null).mayBeSupported()) {
                    return true;
                }
            } else {
                for (String algorithm : algorithms) {
                    if (credentials.getCredentialAcquireSupport(type, algorithm).mayBeSupported()) {
                        return true;
                    }
                }
            }
        }
        return super.filterOneSaslMechanism(mechanismName);
    }

    AuthenticationConfiguration reparent(final AuthenticationConfiguration newParent) {
        return new SetCredentialsConfiguration(newParent, credentialsSupplier, matchPredicate);
    }
}
