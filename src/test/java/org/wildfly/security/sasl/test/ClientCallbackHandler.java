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

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.RealmCallback;
import javax.security.sasl.RealmChoiceCallback;

/**
 * A simple CallbackHandler for testing the client side of the calls.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class ClientCallbackHandler implements CallbackHandler {

    private final String username;
    private final char[] password;
    private final String hexURPHash;
    private final String realm;

    public ClientCallbackHandler(final String username, final char[] password) {
        this(username, password, null);
    }

    public ClientCallbackHandler(final String username, final char[] password, final String realm) {
        this.username = username;
        this.password = password;
        this.hexURPHash = null;
        this.realm = realm;
    }

    public ClientCallbackHandler(final String username, final String hexURPHash) {
        this(username, hexURPHash, null);
    }

    public ClientCallbackHandler(final String username, final String hexURPHash, final String realm) {
        this.username = username;
        this.password = null;
        this.hexURPHash = hexURPHash;
        this.realm = realm;
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
            } else if (current instanceof RealmChoiceCallback || realm != null) {
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
            } else {
                throw new UnsupportedCallbackException(current, current.getClass().getSimpleName() + " not supported.");
            }
        }
    }
}
