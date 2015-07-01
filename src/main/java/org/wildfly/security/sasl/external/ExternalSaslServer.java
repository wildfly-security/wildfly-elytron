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

import static org.wildfly.security._private.ElytronMessages.log;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.text.Normalizer;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.AuthorizeCallback;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;

import org.wildfly.security.sasl.util.AbstractSaslParticipant;
import org.wildfly.security.util._private.Arrays2;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
final class ExternalSaslServer implements SaslServer {

    private final CallbackHandler cbh;
    private boolean complete;
    private String authorizationID;

    ExternalSaslServer(final CallbackHandler cbh) {
        this.cbh = cbh;
    }

    public String getMechanismName() {
        return External.EXTERNAL;
    }

    public byte[] evaluateResponse(final byte[] response) throws SaslException {
        if (complete) {
            throw log.saslMessageAfterComplete(getMechanismName());
        }
        complete = true;
        String authorizationId;
        if (response.length == 0) {
            authorizationId = null;
        } else try {
            authorizationId = Normalizer.normalize(new String(response, "UTF-8"), Normalizer.Form.NFKC);
            if (authorizationId.indexOf(0) != -1) {
                throw log.saslUserNameContainsInvalidCharacter(getMechanismName());
            }
        } catch (UnsupportedEncodingException e) {
            throw log.saslUserNameDecodeFailed(getMechanismName(), "UTF-8");
        }
        final AuthorizeCallback authorizeCallback = new AuthorizeCallback(null, authorizationId);
        try {
            cbh.handle(Arrays2.of(authorizeCallback));
        } catch (SaslException e) {
            throw e;
        } catch (IOException e) {
            throw log.saslAuthorizationFailed(getMechanismName(), e);
        } catch (UnsupportedCallbackException e) {
            throw log.saslAuthorizationFailed(getMechanismName(), e);
        }
        if (!authorizeCallback.isAuthorized()) {
            throw log.saslAuthorizationFailed(getMechanismName(), null, authorizationId);
        }
        this.authorizationID = authorizeCallback.getAuthorizedID();
        return AbstractSaslParticipant.NO_BYTES;
    }

    public boolean isComplete() {
        return complete;
    }

    public String getAuthorizationID() {
        if (! complete) {
            throw log.saslAuthenticationNotComplete(getMechanismName());
        }
        return authorizationID;
    }

    public byte[] unwrap(final byte[] incoming, final int offset, final int len) throws SaslException {
        if (complete) {
            throw log.saslNoSecurityLayer(getMechanismName());
        } else {
            throw log.saslAuthenticationNotComplete(getMechanismName());
        }
    }

    public byte[] wrap(final byte[] outgoing, final int offset, final int len) throws SaslException {
        if (complete) {
            throw log.saslNoSecurityLayer(getMechanismName());
        } else {
            throw log.saslAuthenticationNotComplete(getMechanismName());
        }
    }

    public Object getNegotiatedProperty(final String propName) {
        return null;
    }

    public void dispose() throws SaslException {
    }
}
