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

package org.wildfly.security.sasl.external;

import static org.wildfly.security.mechanism._private.ElytronMessages.saslExternal;

import java.nio.charset.StandardCharsets;

import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;

import org.wildfly.security.sasl.util.AbstractSaslParticipant;
import org.wildfly.security.sasl.util.SaslMechanismInformation;
import org.wildfly.security.sasl.util.SaslWrapper;

final class ExternalSaslClient implements SaslClient, SaslWrapper {

    private final byte[] authorizationId;

    private boolean complete;

    ExternalSaslClient(final String authorizationId) {
        this.authorizationId = authorizationId == null ? AbstractSaslParticipant.NO_BYTES : authorizationId.getBytes(StandardCharsets.UTF_8);
    }

    public String getMechanismName() {
        return SaslMechanismInformation.Names.EXTERNAL;
    }

    public boolean hasInitialResponse() {
        return true;
    }

    public byte[] evaluateChallenge(final byte[] challenge) throws SaslException {
        if (challenge.length != 0) {
            throw saslExternal.mechInvalidMessageReceived().toSaslException();
        }
        if (complete) {
            throw saslExternal.mechMessageAfterComplete().toSaslException();
        }
        complete = true;
        return authorizationId;
    }

    public boolean isComplete() {
        return complete;
    }

    public byte[] unwrap(final byte[] incoming, final int offset, final int len) throws SaslException {
        if (complete) {
            throw saslExternal.mechNoSecurityLayer();
        } else {
            throw saslExternal.mechAuthenticationNotComplete();
        }
    }

    public byte[] wrap(final byte[] outgoing, final int offset, final int len) throws SaslException {
        if (complete) {
            throw saslExternal.mechNoSecurityLayer();
        } else {
            throw saslExternal.mechAuthenticationNotComplete();
        }
    }

    public Object getNegotiatedProperty(final String propName) {
        if (complete) {
            return null;
        } else {
            throw saslExternal.mechAuthenticationNotComplete();
        }
    }

    public void dispose() throws SaslException {
    }
}
