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

package org.jboss.sasl.localuser;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import org.jboss.sasl.util.AbstractSaslClient;
import org.jboss.sasl.util.Charsets;
import org.jboss.sasl.util.SaslState;
import org.jboss.sasl.util.SaslStateContext;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.sasl.RealmCallback;
import javax.security.sasl.SaslException;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class LocalUserClient extends AbstractSaslClient {

    LocalUserClient(final String protocol, final String serverName, final CallbackHandler callbackHandler, final String authorizationId) {
        super(LocalUserSaslFactory.JBOSS_LOCAL_USER, protocol, serverName, callbackHandler, authorizationId, true);
    }

    public void init() {
        getContext().setNegotiationState(new SaslState() {
            public byte[] evaluateMessage(final SaslStateContext context, final byte[] message) throws SaslException {
                final String authorizationId = getAuthorizationId();
                final byte[] bytes = new byte[Charsets.encodedLengthOf(authorizationId)];
                Charsets.encodeTo(authorizationId, bytes, 0);
                context.setNegotiationState(new SaslState() {
                    public byte[] evaluateMessage(final SaslStateContext context, final byte[] message) throws SaslException {
                        final String path = new String(message, Charsets.UTF_8);
                        final File file = new File(path);
                        final byte[] challenge = new byte[8];
                        int t = 0;
                        try {
                            final FileInputStream stream = new FileInputStream(file);
                            while (t < 8) {
                                int r = stream.read(challenge, t, 8-t);
                                if (r < 0) {
                                    throw new SaslException("Invalid server challenge");
                                } else {
                                    t += r;
                                }
                            }
                        } catch (IOException e) {
                            throw new SaslException("Failed to read server challenge", e);
                        }
                        String authenticationId = getAuthorizationId();
                        String authenticationRealm;
                        final NameCallback nameCallback = new NameCallback("User name", authenticationId);
                        final RealmCallback realmCallback = new RealmCallback("User realm");
                        handleCallbacks(nameCallback, realmCallback);
                        authenticationId = nameCallback.getName();
                        authenticationRealm = realmCallback.getText();
                        if (authenticationId == null) authenticationId = "";
                        if (authenticationRealm == null) authenticationRealm = "";
                        final int authenticationIdLength = Charsets.encodedLengthOf(authenticationId);
                        final int authenticationRealmLength = Charsets.encodedLengthOf(authenticationRealm);
                        final byte[] response = new byte[8 + 1 + authenticationIdLength + authenticationRealmLength];
                        System.arraycopy(challenge, 0, response, 0, 8);
                        Charsets.encodeTo(authenticationId, response, 8);
                        Charsets.encodeTo(authenticationRealm, response, 8 + 1 + authenticationIdLength);
                        context.negotiationComplete();
                        return response;
                    }
                });
                return bytes;
            }
        });
    }
}
