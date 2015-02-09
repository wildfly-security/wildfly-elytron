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

package org.wildfly.security.sasl.localuser;

import java.io.Closeable;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import org.wildfly.security.sasl.util.AbstractSaslClient;
import org.wildfly.security.util.ByteStringBuilder;
import org.wildfly.security.util.CodePointIterator;

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

    private static final int INITIAL_CHALLENGE_STATE = 1;
    private static final int CHALLENGE_RESPONSE_STATE = 2;

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
        setNegotiationState(INITIAL_CHALLENGE_STATE);
    }

    @Override
    protected byte[] evaluateMessage(int state, final byte[] message) throws SaslException {
        switch (state) {
            case INITIAL_CHALLENGE_STATE:
                final String authorizationId = getAuthorizationId();
                final byte[] bytes;
                if (authorizationId != null) {
                    bytes = CodePointIterator.ofString(authorizationId).asUtf8(true).drain();
                } else {
                    bytes = new byte[] { UTF8NUL };
                }
                setNegotiationState(CHALLENGE_RESPONSE_STATE);
                return bytes;
            case CHALLENGE_RESPONSE_STATE:
                final String path = new String(message, StandardCharsets.UTF_8);
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
                ByteStringBuilder b = new ByteStringBuilder();
                b.append(challenge, 0, 8);
                b.append(authenticationId).append((byte) 0).append(authenticationRealm);
                final byte[] response = b.toArray();
                negotiationComplete();
                return response;
        }
        throw new SaslException("Invalid state");
    }

    private static void safeClose(Closeable c) {
        if (c != null) try {
            c.close();
        } catch (Throwable ignored) {}
    }
}
