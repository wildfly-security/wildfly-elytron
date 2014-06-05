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

package org.wildfly.sasl.localuser;

import java.io.Closeable;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Map;

import org.wildfly.sasl.util.AbstractSaslClient;
import org.wildfly.sasl.util.Charsets;
import org.wildfly.sasl.util.SaslState;
import org.wildfly.sasl.util.SaslStateContext;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.sasl.RealmCallback;
import javax.security.sasl.SaslException;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class LocalUserClient extends AbstractSaslClient {

    public static final String QUIET_AUTH = "wildfly.sasl.local-user.quiet-auth";
    public static final String LEGACY_QUIET_AUTH = "jboss.sasl.local-user.quiet-auth";

    private final boolean quietAuth;

    private static final byte UTF8NUL = 0x00;

    LocalUserClient(final String protocol, final String serverName, final Map<String, ?> props, final CallbackHandler callbackHandler, final String authorizationId) {
        super(LocalUserSaslFactory.JBOSS_LOCAL_USER, protocol, serverName, callbackHandler, authorizationId, true);

        if (props.containsKey(QUIET_AUTH)) {
            quietAuth = Boolean.parseBoolean((String) props.get(QUIET_AUTH));
        } else if (props.containsKey(LEGACY_QUIET_AUTH)) {
            quietAuth = Boolean.parseBoolean((String) props.get(LEGACY_QUIET_AUTH));
        } else {
            quietAuth = false;
        }
    }

    public void init() {
        getContext().setNegotiationState(new SaslState() {
            public byte[] evaluateMessage(final SaslStateContext context, final byte[] message) throws SaslException {
                final String authorizationId = getAuthorizationId();
                final byte[] bytes;
                if (authorizationId != null) {
                    bytes = new byte[Charsets.encodedLengthOf(authorizationId)];
                    Charsets.encodeTo(authorizationId, bytes, 0);
                } else {
                    bytes = new byte[] { UTF8NUL };
                }
                context.setNegotiationState(new SaslState() {
                    public byte[] evaluateMessage(final SaslStateContext context, final byte[] message) throws SaslException {
                        final String path = new String(message, Charsets.UTF_8);
                        final File file = new File(path);
                        final byte[] challenge = new byte[8];
                        int t = 0;
                        try {
                            final FileInputStream stream = new FileInputStream(file);
                            try {
                                while (t < 8) {
                                    int r = stream.read(challenge, t, 8-t);
                                    if (r < 0) {
                                        throw new SaslException("Invalid server challenge");
                                    } else {
                                        t += r;
                                    }
                                }
                            } finally {
                                safeClose(stream);
                            }
                        } catch (IOException e) {
                            throw new SaslException("Failed to read server challenge", e);
                        }
                        String authenticationId = getAuthorizationId();
                        String authenticationRealm = null;
                        if (quietAuth == false) {
                            final NameCallback nameCallback = authenticationId != null ? new NameCallback("User name",
                                    authenticationId) : new NameCallback("User name");
                            final RealmCallback realmCallback = new RealmCallback("User realm");
                            handleCallbacks(nameCallback, realmCallback);
                            authenticationId = nameCallback.getName();
                            authenticationRealm = realmCallback.getText();
                        }
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

    private static void safeClose(Closeable c) {
        if (c != null) try {
            c.close();
        } catch (Throwable ignored) {}
    }
}
