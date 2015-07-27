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
import java.security.spec.KeySpec;
import java.util.Arrays;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.AuthorizeCallback;
import javax.security.sasl.RealmCallback;
import javax.security.sasl.SaslException;

import org.junit.Assert;
import org.wildfly.security.auth.callback.AnonymousAuthorizationCallback;
import org.wildfly.security.auth.callback.ChannelBindingCallback;
import org.wildfly.security.auth.callback.CredentialCallback;
import org.wildfly.security.auth.callback.PasswordVerifyCallback;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactory;

/**
 * A server side callback handler for use with the test cases to trigger
 * required failures.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 * @deprecated Use real callback handlers where possible
 */
@Deprecated
public class ServerCallbackHandler implements CallbackHandler {

    private final String expectedUsername;
    private final char[] expectedPassword;
    private final String expectedAuthzid;
    private final KeySpec keySpec;
    private final String algorithm;
    private String bindingType = null;
    private byte[] bindingData = null;

    public ServerCallbackHandler(final String expectedUsername, final char[] expectedPassword) {
        this.expectedUsername = expectedUsername;
        this.expectedPassword = expectedPassword;
        expectedAuthzid = null;
        keySpec = null;
        algorithm = null;
    }

    public ServerCallbackHandler(final String expectedUsername, final String algorithm, KeySpec keyspec) {
        this.expectedUsername = expectedUsername;
        this.algorithm = algorithm;
        this.keySpec = keyspec;
        expectedAuthzid = null;
        expectedPassword = null;
    }

    public ServerCallbackHandler(final String expectedUsername, final String algorithm, KeySpec keyspec, String authzid) {
        this.expectedUsername = expectedUsername;
        this.algorithm = algorithm;
        this.keySpec = keyspec;
        expectedAuthzid = authzid;
        expectedPassword = null;
    }

    public void setBinding(String bindingType, byte[] bindingData){
        this.bindingType = bindingType;
        this.bindingData = bindingData;
    }

    @Override
    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        for (Callback current : callbacks) {
            if (current instanceof NameCallback) {
                String username = ((NameCallback) current).getDefaultName();
                if (username == null || username.equals(expectedUsername) == false) {
                    throw new SaslException("Invalid username received (expected \"" + expectedUsername + "\", received \"" + username + "\"");
                }
            } else if (current instanceof PasswordVerifyCallback && expectedPassword != null) {
                PasswordVerifyCallback pvc = (PasswordVerifyCallback) current;
                pvc.setVerified(Arrays.equals(expectedPassword, pvc.getPassword()));
            } else if (current instanceof PasswordCallback && expectedPassword != null) {
                PasswordCallback pcb = (PasswordCallback) current;
                pcb.setPassword(expectedPassword);
            } else if (current instanceof AnonymousAuthorizationCallback) {
                ((AnonymousAuthorizationCallback) current).setAuthorized(true);
            } else if (current instanceof AuthorizeCallback) {
                AuthorizeCallback acb = (AuthorizeCallback) current;
                Assert.assertEquals(expectedUsername, acb.getAuthenticationID());
                if(expectedAuthzid != null){
                    acb.setAuthorized(expectedAuthzid.equals(acb.getAuthorizationID()));
                }else{
                    acb.setAuthorized(expectedUsername.equals(acb.getAuthorizationID()));
                }
            } else if (current instanceof RealmCallback) {
            } else if (current instanceof CredentialCallback && algorithm != null && keySpec != null) {
                CredentialCallback ccb = (CredentialCallback) current;
                try {
                    PasswordFactory passwordFactory = PasswordFactory.getInstance(algorithm);
                    Password password = passwordFactory.generatePassword(keySpec);
                    if (ccb.isCredentialSupported(password)) {
                        ccb.setCredential(password);
                    }
                } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                    throw new IOException("Password object generation failed", e);
                }
            } else if (current instanceof ChannelBindingCallback && bindingType != null) {
                ChannelBindingCallback cbc = (ChannelBindingCallback) current;
                cbc.setBindingType(bindingType);
                cbc.setBindingData(bindingData);
            } else {
                throw new UnsupportedCallbackException(current, current.getClass().getSimpleName() + " not supported.");
            }
        }

    }
}
