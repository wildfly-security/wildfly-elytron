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

import static org.wildfly.security.mechanism._private.ElytronMessages.saslLocal;

import java.io.Closeable;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.RealmCallback;
import javax.security.sasl.SaslException;

import org.wildfly.common.Assert;
import org.wildfly.common.bytes.ByteStringBuilder;
import org.wildfly.common.iteration.CodePointIterator;
import org.wildfly.security.auth.callback.OptionalNameCallback;
import org.wildfly.security.sasl.util.AbstractSaslClient;

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
        super(LocalUserSaslFactory.JBOSS_LOCAL_USER, protocol, serverName, callbackHandler, authorizationId, true, saslLocal);

        if (props == null) {
            quietAuth = false;
        } else if (props.containsKey(QUIET_AUTH)) {
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
                                throw saslLocal.mechInvalidServerMessage().toSaslException();
                            } else {
                                t += r;
                            }
                        }
                    } finally {
                        safeClose(stream);
                    }
                } catch (IOException e) {
                    throw saslLocal.mechFailedToReadChallengeFile(e).toSaslException();
                }
                String authenticationId = getAuthorizationId();
                String authenticationRealm = null;
                if (quietAuth == false) {
                    final NameCallback nameCallback = authenticationId != null && ! authenticationId.isEmpty() ?
                            new OptionalNameCallback("User name", authenticationId) : new OptionalNameCallback("User name");
                    final RealmCallback realmCallback = new RealmCallback("User realm");

                    try {
                        tryHandleCallbacks(nameCallback, realmCallback);
                        authenticationId = nameCallback.getName();
                        authenticationRealm = realmCallback.getText();
                    } catch (UnsupportedCallbackException e) {
                        saslLocal.trace("CallbackHandler does not support name or realm callback", e);
                    }
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
        throw Assert.impossibleSwitchCase(state);
    }

    private static void safeClose(Closeable c) {
        if (c != null) try {
            c.close();
        } catch (Throwable ignored) {}
    }
}
