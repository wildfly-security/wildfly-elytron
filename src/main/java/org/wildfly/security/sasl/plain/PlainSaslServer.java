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
import static org.wildfly.security.sasl.plain.PlainSasl.PLAIN;

import java.io.IOException;
import java.util.NoSuchElementException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.AuthorizeCallback;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;

import org.wildfly.security.sasl.callback.VerifyPasswordCallback;
import org.wildfly.security.sasl.util.SaslWrapper;
import org.wildfly.security.util.CodePointIterator;

/**
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
final class PlainSaslServer implements SaslServer, SaslWrapper {

    private final CallbackHandler callbackHandler;
    private boolean complete;
    private String authorizedId;

    /**
     * Construct a new instance.
     *
     * @param callbackHandler the callback handler
     */
    public PlainSaslServer(final CallbackHandler callbackHandler) {
        this.callbackHandler = callbackHandler;
    }

    public String getAuthorizationID() {
        if (! isComplete()) {
            throw log.saslAuthenticationNotComplete();
        }
        return authorizedId;
    }

    public String getMechanismName() {
        return PLAIN;
    }

    public boolean isComplete() {
        return complete;
    }

    public byte[] evaluateResponse(final byte[] response) throws SaslException {
        if (complete) {
            throw log.saslMessageAfterComplete();
        }
        complete = true;
        if (response.length >= 65536) {
            throw log.saslMessageTooLong();
        }
        CodePointIterator i = CodePointIterator.ofUtf8Bytes(response);
        String authorizationId;
        String loginName;
        String password;
        try {
            final CodePointIterator delimIter = i.delimitedBy(0);
            authorizationId = delimIter.hasNext() ? delimIter.drainToString() : null;
            i.next(); // skip delimiter
            loginName = delimIter.drainToString();
            i.next(); // skip delimiter
            password = delimIter.drainToString();
            if (authorizationId == null) {
                authorizationId = loginName;
            }
        } catch (NoSuchElementException ignored) {
            throw log.saslInvalidMessageReceived();
        }

        // The message has now been parsed, split and converted to UTF-8 Strings
        // now it is time to use the CallbackHandler to validate the supplied credentials.

        // First verify username and password.

        NameCallback ncb = new NameCallback("PLAIN authentication identity", loginName);
        VerifyPasswordCallback vpc = new VerifyPasswordCallback(password);

        try {
            callbackHandler.handle(new Callback[] { ncb, vpc });
        } catch (SaslException e) {
            throw e;
        } catch (IOException | UnsupportedCallbackException e) {
            throw log.saslServerSideAuthenticationFailed(e);
        }

        if (vpc.isVerified() == false) {
            throw log.saslPasswordNotVerified();
        }

        // Now check the authorization id

        AuthorizeCallback acb = new AuthorizeCallback(loginName, authorizationId);
        try {
            callbackHandler.handle(new Callback[] { acb });
        } catch (SaslException e) {
            throw e;
        } catch (IOException | UnsupportedCallbackException e) {
            throw log.saslServerSideAuthenticationFailed(e);
        }

        if (acb.isAuthorized() == true) {
            authorizedId = acb.getAuthorizedID();
        } else {
            throw log.saslAuthorizationFailed(loginName, authorizationId);
        }
        return null;
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
