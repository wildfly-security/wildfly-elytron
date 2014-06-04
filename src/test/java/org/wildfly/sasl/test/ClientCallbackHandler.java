/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2011, Red Hat, Inc., and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
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
