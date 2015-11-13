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

package org.wildfly.security.auth.util;

import static java.security.AccessController.doPrivileged;

import java.io.IOException;
import java.net.Authenticator;
import java.net.PasswordAuthentication;
import java.net.URISyntaxException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.wildfly.security.auth.callback.CredentialCallback;
import org.wildfly.security.auth.client.AuthenticationConfiguration;
import org.wildfly.security.auth.client.AuthenticationContext;
import org.wildfly.security.auth.client.AuthenticationContextConfigurationClient;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.TwoWayPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.permission.ElytronPermission;

/**
 * An implementation of {@link Authenticator} which uses the current security context to perform the authentication.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class ElytronAuthenticator extends Authenticator {

    private static final AuthenticationContextConfigurationClient client = doPrivileged(AuthenticationContextConfigurationClient.ACTION);
    private static final ElytronPermission CREATE_AUTHENTICATOR_PERMISSION = new ElytronPermission("createAuthenticator");

    /**
     * Construct a new instance.  Requires the {@code createAuthenticator} {@link ElytronPermission}.
     */
    public ElytronAuthenticator() {
        final SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            sm.checkPermission(CREATE_AUTHENTICATOR_PERMISSION);
        }
    }

    /**
     * Get the password authentication for this authenticator, which uses the current local
     * {@linkplain AuthenticationContext authentication context} to log in to the remote server.
     *
     * @return the authenticator
     */
    protected PasswordAuthentication getPasswordAuthentication() {
        final AuthenticationContext context = AuthenticationContext.captureCurrent();
        final AuthenticationConfiguration authenticationConfiguration;
        try {
            authenticationConfiguration = client.getAuthenticationConfiguration(getRequestingURL().toURI(), context);
        } catch (URISyntaxException e) {
            return null;
        }
        if (authenticationConfiguration == null) return null;
        final CallbackHandler callbackHandler = client.getCallbackHandler(authenticationConfiguration);
        final NameCallback nameCallback = new NameCallback(getRequestingPrompt());
        final CredentialCallback credentialCallback = new CredentialCallback(PasswordCredential.class);

        char[] password = null;
        try {
            callbackHandler.handle(new Callback[] { nameCallback, credentialCallback });
            final PasswordCredential credential = (PasswordCredential) credentialCallback.getCredential();
            final TwoWayPassword twoWayPassword = credential.getPassword(TwoWayPassword.class);
            final PasswordFactory factory = PasswordFactory.getInstance(twoWayPassword.getAlgorithm());
            final ClearPasswordSpec keySpec = factory.getKeySpec(twoWayPassword, ClearPasswordSpec.class);
            password = keySpec.getEncodedPassword();
        } catch (UnsupportedCallbackException e) {
            if (e.getCallback() == credentialCallback) {
                // try again with a password callback
                final PasswordCallback passwordCallback = new PasswordCallback("Password", false);
                try {
                    callbackHandler.handle(new Callback[] { nameCallback, passwordCallback });
                    password = passwordCallback.getPassword();
                } catch (IOException | UnsupportedCallbackException e1) {
                    return null;
                }
            }
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            return null;
        }
        final String name = nameCallback.getName();
        if (name == null || password == null) return null;
        return new PasswordAuthentication(name, password);
    }
}
