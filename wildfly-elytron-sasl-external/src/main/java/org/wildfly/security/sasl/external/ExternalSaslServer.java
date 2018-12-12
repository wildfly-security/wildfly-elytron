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

import static org.wildfly.security._private.ElytronMessages.saslExternal;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.text.Normalizer;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.AuthorizeCallback;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;

import org.wildfly.common.array.Arrays2;
import org.wildfly.security.sasl.util.SaslMechanismInformation;

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
        return SaslMechanismInformation.Names.EXTERNAL;
    }

    public byte[] evaluateResponse(final byte[] response) throws SaslException {
        if (complete) {
            throw saslExternal.mechMessageAfterComplete().toSaslException();
        }
        complete = true;
        String authorizationId;
        if (response.length == 0) {
            authorizationId = null;
        } else {
            authorizationId = Normalizer.normalize(new String(response, StandardCharsets.UTF_8), Normalizer.Form.NFKC);
            if (authorizationId.indexOf(0) != -1) {
                throw saslExternal.mechUserNameContainsInvalidCharacter().toSaslException();
            }
        }
        final AuthorizeCallback authorizeCallback = new AuthorizeCallback(null, authorizationId);
        try {
            cbh.handle(Arrays2.of(authorizeCallback));
        } catch (SaslException e) {
            throw e;
        } catch (IOException e) {
            throw saslExternal.mechAuthorizationFailed(e).toSaslException();
        } catch (UnsupportedCallbackException e) {
            throw saslExternal.mechAuthorizationFailed(e).toSaslException();
        }
        if (!authorizeCallback.isAuthorized()) {
            throw saslExternal.mechAuthorizationFailed(null, authorizationId).toSaslException();
        }
        this.authorizationID = authorizeCallback.getAuthorizedID();
        return null;
    }

    public boolean isComplete() {
        return complete;
    }

    public String getAuthorizationID() {
        if (! complete) {
            throw saslExternal.mechAuthenticationNotComplete();
        }
        return authorizationID;
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
