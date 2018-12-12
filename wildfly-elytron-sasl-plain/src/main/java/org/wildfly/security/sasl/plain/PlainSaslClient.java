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

import static org.wildfly.security.mechanism._private.ElytronMessages.saslPlain;

import java.io.IOException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;

import org.wildfly.common.bytes.ByteStringBuilder;
import org.wildfly.security.sasl.util.SaslMechanismInformation;
import org.wildfly.security.sasl.util.SaslWrapper;
import org.wildfly.security.sasl.util.StringPrep;

/**
 * The {@code PLAIN} SASL client implementation.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
final class PlainSaslClient implements SaslClient, SaslWrapper {

    private final String authorizationId;
    private final CallbackHandler cbh;
    private boolean complete = false;

    PlainSaslClient(final String authorizationId, final CallbackHandler cbh) {
        this.authorizationId = authorizationId;
        this.cbh = cbh;
    }

    public String getMechanismName() {
        return SaslMechanismInformation.Names.PLAIN;
    }

    public boolean hasInitialResponse() {
        return true;
    }

    public byte[] evaluateChallenge(final byte[] challenge) throws SaslException {
        if (complete) {
            throw saslPlain.mechMessageAfterComplete().toSaslException();
        }
        complete = true;
        if (challenge.length > 0) {
            throw saslPlain.mechInvalidMessageReceived().toSaslException();
        }
        final NameCallback nameCallback = new NameCallback("Login name");
        final PasswordCallback passwordCallback = new PasswordCallback("Password", false);
        try {
            cbh.handle(new Callback[] { nameCallback, passwordCallback });
        } catch (SaslException e) {
            throw e;
        } catch (IOException | UnsupportedCallbackException e) {
            throw saslPlain.mechCallbackHandlerFailedForUnknownReason(e).toSaslException();
        }
        final String name = nameCallback.getName();
        if (name == null) {
            throw saslPlain.mechNoLoginNameGiven().toSaslException();
        }
        final char[] password = passwordCallback.getPassword();
        if (password == null) {
            throw saslPlain.mechNoPasswordGiven().toSaslException();
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
            throw saslPlain.mechMalformedFields(ex).toSaslException();
        }
    }

    public boolean isComplete() {
        return complete;
    }

    public byte[] unwrap(final byte[] incoming, final int offset, final int len) throws SaslException {
        if (complete) {
            throw saslPlain.mechNoSecurityLayer();
        } else {
            throw saslPlain.mechAuthenticationNotComplete();
        }
    }

    public byte[] wrap(final byte[] outgoing, final int offset, final int len) throws SaslException {
        if (complete) {
            throw saslPlain.mechNoSecurityLayer();
        } else {
            throw saslPlain.mechAuthenticationNotComplete();
        }
    }

    public Object getNegotiatedProperty(final String propName) {
        if (complete) {
            return null;
        } else {
            throw saslPlain.mechAuthenticationNotComplete();
        }
    }

    public void dispose() throws SaslException {
    }
}
