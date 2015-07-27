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

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.RealmCallback;
import javax.security.sasl.RealmChoiceCallback;

import org.wildfly.security.auth.callback.ChannelBindingCallback;
import org.wildfly.security.auth.callback.CredentialCallback;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactory;

/**
 * A simple CallbackHandler for testing the client side of the calls.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 * @deprecated Use real callback handlers where possible
 */
@Deprecated
public class ClientCallbackHandler implements CallbackHandler {

    private final String username;
    private final char[] password;
    private final KeySpec keySpec;
    private final String realm;
    private final String algorithm;
    private String bindingType = null;
    private byte[] bindingData = null;

    public ClientCallbackHandler(final String username, final char[] password) {
        this(username, password, null);
    }

    public ClientCallbackHandler(final String username, final char[] password, final String realm) {
        this.username = username;
        this.password = password;
        this.keySpec = null;
        this.realm = realm;
        this.algorithm = null;
    }

    public ClientCallbackHandler(final String username, final String realm, final String algorithm, KeySpec keySpec) {
        this.username = username;
        this.realm = realm;
        this.password = null;
        this.algorithm = algorithm;
        this.keySpec = keySpec;
    }

    public void setBinding(String bindingType, byte[] bindingData){
        this.bindingType = bindingType;
        this.bindingData = bindingData;
    }

    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        for (Callback current : callbacks) {
            if (current instanceof NameCallback) {
                NameCallback ncb = (NameCallback) current;
                ncb.setName(username);
            } else if (current instanceof PasswordCallback && password != null) {
                PasswordCallback pcb = (PasswordCallback) current;
                pcb.setPassword(password);
            } else if (current instanceof RealmCallback) {
                RealmCallback rcb = (RealmCallback) current;
                if (realm == null) {
                    String defaultText = rcb.getDefaultText();
                    if (defaultText != null && defaultText.length() > 0) {
                        rcb.setText(defaultText);
                    }
                } else {
                    rcb.setText(realm);
                }
            } else if (current instanceof RealmChoiceCallback && realm != null) {
                RealmChoiceCallback rcb = (RealmChoiceCallback) current;
                boolean selected = false;
                String[] choices = rcb.getChoices();
                for(int i = 0; i < choices.length; i++){
                    if(choices[i].equals(realm)){
                        rcb.setSelectedIndex(i);
                        selected = true;
                    }
                }
                if(!selected){
                    throw new UnsupportedCallbackException(current, "Realm which should be selected is not in choices.");
                }
            } else if (current instanceof CredentialCallback && algorithm != null && keySpec != null) {
                CredentialCallback ccb = (CredentialCallback) current;
                try {
                    PasswordFactory passwordFactory = PasswordFactory.getInstance(algorithm);
                    Password password = passwordFactory.generatePassword(keySpec);

                    ccb.setCredential(password);
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
