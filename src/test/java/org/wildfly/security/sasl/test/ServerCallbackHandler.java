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
package org.wildfly.security.sasl.test;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.AuthorizeCallback;
import javax.security.sasl.RealmCallback;
import javax.security.sasl.SaslException;

import org.wildfly.security.auth.callback.AnonymousAuthorizationCallback;
import org.wildfly.security.auth.callback.CredentialCallback;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.spec.DigestPasswordSpec;
import org.wildfly.security.sasl.callback.VerifyPasswordCallback;

/**
 * A server side callback handler for use with the test cases to trigger
 * required failures.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class ServerCallbackHandler implements CallbackHandler {

    private final String expectedUsername;
    private final char[] expectedPassword;
    private final byte[] urpHash;
    private final String realm;
    private final String algorithm;

    public ServerCallbackHandler(final String expectedUsername, final char[] expectedPassword) {
        this.expectedUsername = expectedUsername;
        this.expectedPassword = expectedPassword;
        urpHash = null;
        realm = null;
        algorithm = null;
    }

    public ServerCallbackHandler(final String expectedUsername, final String realm, final String algorithm, final byte[] urpHash) {
        this.expectedUsername = expectedUsername;
        this.realm = realm;
        this.algorithm = algorithm;
        this.urpHash = urpHash;
        expectedPassword = null;
    }

    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        for (Callback current : callbacks) {
            if (current instanceof NameCallback) {
                String username = ((NameCallback) current).getDefaultName();
                if (username == null || username.equals(expectedUsername) == false) {
                    throw new SaslException("Invalid username received (expected \"" + expectedUsername + "\", received \"" + username + "\"");
                }
            } else if (current instanceof PasswordCallback && expectedPassword != null) {
                PasswordCallback pcb = (PasswordCallback) current;
                pcb.setPassword(expectedPassword);
            } else if (current instanceof VerifyPasswordCallback && expectedPassword != null) {
                VerifyPasswordCallback vcb = (VerifyPasswordCallback) current;
                vcb.setVerified(String.valueOf(expectedPassword).equals(vcb.getPassword()));
            } else if (current instanceof AnonymousAuthorizationCallback) {
                ((AnonymousAuthorizationCallback) current).setAuthorized(true);
            } else if (current instanceof AuthorizeCallback) {
                AuthorizeCallback acb = (AuthorizeCallback) current;
                acb.setAuthorized(acb.getAuthenticationID().equals(acb.getAuthorizationID()));
            } else if (current instanceof RealmCallback) {
            } else if (current instanceof CredentialCallback && algorithm != null && urpHash != null) {
                CredentialCallback ccb = (CredentialCallback) current;
                try {
                    PasswordFactory passwordFactory = PasswordFactory.getInstance(algorithm);
                    Password password = passwordFactory.generatePassword(new DigestPasswordSpec(algorithm, expectedUsername, realm, urpHash));
                    ccb.setCredential(password);
                } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                    throw new IOException("Password object generation failed", e);
                }
            } else {
                throw new UnsupportedCallbackException(current, current.getClass().getSimpleName() + " not supported.");
            }
        }

    }
}
