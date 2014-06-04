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
import javax.security.sasl.AuthorizeCallback;
import javax.security.sasl.RealmCallback;

import java.io.IOException;

import org.wildfly.sasl.callback.DigestHashCallback;
import org.wildfly.sasl.callback.VerifyPasswordCallback;

/**
 * A server side callback handler for use with the test cases to trigger
 * required failures.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class ServerCallbackHandler implements CallbackHandler {

    private final String expectedUsername;
    private final char[] expectedPassword;
    private final String hexURPHash;

    ServerCallbackHandler(final String expectedUsername, final char[] expectedPassword) {
        this.expectedUsername = expectedUsername;
        this.expectedPassword = expectedPassword;
        hexURPHash = null;
    }

    ServerCallbackHandler(final String expectedUsername, final String hexURPHash) {
        this.expectedUsername = expectedUsername;
        this.hexURPHash = hexURPHash;
        expectedPassword = null;
    }

    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {

        for (Callback current : callbacks) {
            if (current instanceof NameCallback) {
                String username = ((NameCallback) current).getDefaultName();
                if (username == null || username.equals(expectedUsername) == false) {
                    throw new IOException("Invalid username received.");
                }
            } else if (current instanceof PasswordCallback && expectedPassword != null) {
                PasswordCallback pcb = (PasswordCallback) current;
                pcb.setPassword(expectedPassword);
            } else if (current instanceof VerifyPasswordCallback && expectedPassword != null) {
                VerifyPasswordCallback vcb = (VerifyPasswordCallback) current;
                vcb.setVerified(String.valueOf(expectedPassword).equals(vcb.getPassword()));
            } else if (current instanceof DigestHashCallback && hexURPHash != null) {
                DigestHashCallback dhc = (DigestHashCallback) current;
                dhc.setHexHash(hexURPHash);
            } else if (current instanceof AuthorizeCallback) {
                AuthorizeCallback acb = (AuthorizeCallback) current;
                acb.setAuthorized(acb.getAuthenticationID().equals(acb.getAuthorizationID()));
            } else if (current instanceof RealmCallback) {
            } else {
                throw new UnsupportedCallbackException(current, current.getClass().getSimpleName() + " not supported.");
            }
        }

    }
}
