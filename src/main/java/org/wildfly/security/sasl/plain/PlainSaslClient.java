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

package org.wildfly.security.sasl.plain;

import static org.wildfly.security._private.ElytronMessages.log;

import java.io.IOException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;

import org.wildfly.security.sasl.util.SaslWrapper;
import org.wildfly.security.sasl.util.StringPrep;
import org.wildfly.security.util.ByteStringBuilder;

/**
 * The {@code PLAIN} SASL client implementation.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
class PlainSaslClient implements SaslClient, SaslWrapper {

    private final String authorizationId;
    private final CallbackHandler cbh;
    private boolean complete = false;

    PlainSaslClient(final String authorizationId, final CallbackHandler cbh) {
        this.authorizationId = authorizationId;
        this.cbh = cbh;
    }

    public String getMechanismName() {
        return PlainSasl.PLAIN;
    }

    public boolean hasInitialResponse() {
        return true;
    }

    public byte[] evaluateChallenge(final byte[] challenge) throws SaslException {
        if (complete) {
            throw log.saslMessageAfterComplete();
        }
        complete = true;
        if (challenge.length > 0) {
            throw log.saslInvalidMessageReceived();
        }
        final NameCallback nameCallback = new NameCallback("Login name");
        final PasswordCallback passwordCallback = new PasswordCallback("Password", false);
        try {
            cbh.handle(new Callback[] { nameCallback, passwordCallback });
        } catch (SaslException e) {
            throw e;
        } catch (IOException | UnsupportedCallbackException e) {
            throw log.saslClientSideAuthenticationFailed(e);
        }
        final String name = nameCallback.getName();
        if (name == null) {
            throw log.saslNoLoginNameGiven();
        }
        final char[] password = passwordCallback.getPassword();
        if (password == null) {
            throw log.saslNoPasswordGiven();
        }
        try {
            final ByteStringBuilder b = new ByteStringBuilder();
            if (authorizationId != null) {
                StringPrep.encode(authorizationId, b, StringPrep.PROFILE_SASL_STORED);
            }
            b.append((byte) 0);
            StringPrep.encode(name, b, StringPrep.PROFILE_SASL_STORED);
            b.append((byte) 0);
            StringPrep.encode(password, b, StringPrep.PROFILE_SASL_STORED);
            return b.toArray();
        } catch (IllegalArgumentException ex) {
            throw log.saslMalformedFields(ex);
        }
    }

    public boolean isComplete() {
        return complete;
    }

    public byte[] unwrap(final byte[] incoming, final int offset, final int len) throws SaslException {
        if (complete) {
            throw log.saslAuthenticationNotComplete();
        } else {
            throw log.saslNoSecurityLayer();
        }
    }

    public byte[] wrap(final byte[] outgoing, final int offset, final int len) throws SaslException {
        if (complete) {
            throw log.saslAuthenticationNotComplete();
        } else {
            throw log.saslNoSecurityLayer();
        }
    }

    public Object getNegotiatedProperty(final String propName) {
        return null;
    }

    public void dispose() throws SaslException {
    }
}
