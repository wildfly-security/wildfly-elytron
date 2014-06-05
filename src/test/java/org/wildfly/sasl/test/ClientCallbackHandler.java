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
package org.wildfly.sasl.test;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.RealmCallback;

import org.wildfly.sasl.callback.DigestHashCallback;

import java.io.IOException;

/**
 * A simple CallbackHandler for testing the client side of the calls.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class ClientCallbackHandler implements CallbackHandler {

    private final String username;
    private final char[] password;
    private final String hexURPHash;
    private final String realm;

    ClientCallbackHandler(final String username, final char[] password) {
        this(username, password, null);
    }

    ClientCallbackHandler(final String username, final char[] password, final String realm) {
        this.username = username;
        this.password = password;
        this.realm = realm;
        this.hexURPHash = null;
    }
    
    ClientCallbackHandler(final String username, final String hexURPHash) {
        this(username, hexURPHash, null);
    }

    ClientCallbackHandler(final String username, final String hexURPHash, final String realm) {
        this.username = username;
        this.hexURPHash = hexURPHash;
        this.password = null;
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
            } else if (current instanceof DigestHashCallback && hexURPHash != null) {
                DigestHashCallback dhc = (DigestHashCallback) current;
                dhc.setHexHash(hexURPHash);
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
            } else {
                throw new UnsupportedCallbackException(current, current.getClass().getSimpleName() + " not supported.");
            }
        }
    }
}
