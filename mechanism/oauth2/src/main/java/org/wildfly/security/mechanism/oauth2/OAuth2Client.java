/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.mechanism.oauth2;

import static org.wildfly.common.Assert.assertTrue;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.wildfly.common.bytes.ByteStringBuilder;
import org.wildfly.common.iteration.ByteIterator;
import org.wildfly.security.auth.callback.CredentialCallback;
import org.wildfly.security.credential.BearerTokenCredential;
import org.wildfly.security.mechanism._private.ElytronMessages;
import org.wildfly.security.mechanism._private.MechanismUtil;
import org.wildfly.security.mechanism.AuthenticationMechanismException;
import org.wildfly.security.sasl.util.StringPrep;

/**
 * Implementation of the client side of the OAuth2 SASL mechanism.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class OAuth2Client {

    private static final String KV_DELIMITER = "%x01";

    private final CallbackHandler callbackHandler;
    private final String authorizationId;
    private ElytronMessages log;

    /**
     * Constructs a new {@code OAuth2Client} instance.
     *
     * @param authorizationId the ID of the user to be authorized.
     * @param callbackHandler the callback handler for verifying the Bearer token.
     * @param log the logger to use.
     */
    public OAuth2Client(String authorizationId, CallbackHandler callbackHandler, ElytronMessages log) {
        this.authorizationId = authorizationId;
        this.callbackHandler = callbackHandler;
        this.log = log;
    }

    /**
     * Gets the initial response message from the client that will be sent to the server.
     * It retrieves the Bearer token from a callback and constructs an encoded message that includes the token.
     *
     * @return encoded message that includes the Bearer token.
     * @throws AuthenticationMechanismException if an error occurs during the callback or the token is {@code null}.
     */
    public OAuth2InitialClientMessage getInitialResponse() throws AuthenticationMechanismException {
        final CredentialCallback credentialCallback = new CredentialCallback(BearerTokenCredential.class);

        try {
            MechanismUtil.handleCallbacks(log, this.callbackHandler, credentialCallback);
        } catch (UnsupportedCallbackException e) {
            throw log.mechCallbackHandlerUnsupportedCallback(e);
        }

        assertTrue(credentialCallback.isCredentialTypeSupported(BearerTokenCredential.class));

        final String token = credentialCallback.applyToCredential(BearerTokenCredential.class, BearerTokenCredential::getToken);

        if (token == null) {
            throw log.mechNoTokenGiven();
        }

        final ByteStringBuilder encoded = new ByteStringBuilder();

        encoded.append("n").append(",");

        if (this.authorizationId != null) {
            encoded.append('a').append('=');
            StringPrep.encode(this.authorizationId, encoded, StringPrep.PROFILE_SASL_STORED | StringPrep.MAP_SCRAM_LOGIN_CHARS);
        }

        encoded.append(",").append(KV_DELIMITER).append("auth").append("=").append("Bearer").append(" ").append(token).append(KV_DELIMITER);

        return new OAuth2InitialClientMessage(null, null, encoded.toArray());
    }

    /**
     * Handles the server's response to the initial client message.
     *
     * @param serverMessage the byte array containing the server's response.
     * @return {@code null} if the response was successful, aborting the authentication otherwise.
     */
    public byte[] handleServerResponse(byte[] serverMessage) {
        // got a successful response
        if (serverMessage.length == 0) {
            return null;
        }

        // otherwise, server responded with an error message
        try {
            String errorMessage = ByteIterator.ofBytes(serverMessage).asUtf8String().base64Decode().asUtf8String().drainToString();
            log.debugf("Got error message from server [%s].", errorMessage);
        } catch (Exception e) {
            log.errorf(e, "Server returned an unexpected message that is probably an error but could not be parsed.");
        }

        // send a last message to abort the authentication
        return new ByteStringBuilder().append(KV_DELIMITER).toArray();
    }
}
