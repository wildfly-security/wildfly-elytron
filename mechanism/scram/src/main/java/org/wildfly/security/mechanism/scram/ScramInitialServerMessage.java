/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2015 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.mechanism.scram;

/**
 * Initial server message for the SCRAM authentication.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class ScramInitialServerMessage {
    private final ScramInitialClientMessage initialResponse;
    private final byte[] serverNonce;
    private final byte[] salt;
    private final int iterationCount;
    private final byte[] messageBytes;

    /**
     * Constructs a new {@code ScramInitialServerMessage} instance.
     *
     * @param initialResponse the initial client message that this initial server message is responding to.
     * @param serverNonce the server generated nonce.
     * @param salt the salt used for generating salted password.
     * @param iterationCount the iteration count used for generating salted password.
     * @param messageBytes the message in form of byte array.
     */
    ScramInitialServerMessage(final ScramInitialClientMessage initialResponse, final byte[] serverNonce, final byte[] salt, final int iterationCount, final byte[] messageBytes) {
        this.initialResponse = initialResponse;
        this.serverNonce = serverNonce;
        this.salt = salt;
        this.iterationCount = iterationCount;
        this.messageBytes = messageBytes;
    }

    /**
     * Returns the SCRAM mechanism in the initial client message.
     *
     * @return the SCRAM mechanism in the initial client message.
     */
    public ScramMechanism getMechanism() {
        return initialResponse.getMechanism();
    }

    /**
     * Returns the initial client message.
     *
     * @return the initial client message.
     */
    public ScramInitialClientMessage getInitialResponse() {
        return initialResponse;
    }

    /**
     * Returns a copy of the server nonce.
     *
     * @return a copy of the server nonce.
     */
    public byte[] getServerNonce() {
        return serverNonce.clone();
    }

    /**
     * Returns the server nonce.
     *
     * @return the server nonce.
     */
    byte[] getRawServerNonce() {
        return serverNonce;
    }

    /**
     * Returns the iteration count used for generating salted password.
     *
     * @return the iteration count used for generating salted password.
     */
    public int getIterationCount() {
        return iterationCount;
    }

    /**
     * Returns the salt used for generating salted password.
     *
     * @return the salt used for generating salted password.
     */
    byte[] getRawSalt() {
        return salt;
    }

    /**
     * Returns the initial server message in form of byte array.
     *
     * @return the initial server message in form of byte array.
     */
    byte[] getRawMessageBytes() {
        return messageBytes;
    }

    /**
     * Returns a copy of the salt used for generating salted password.
     *
     * @return a copy of the salt used for generating salted password.
     */
    public byte[] getSalt() {
        return salt.clone();
    }

    /**
     * Returns a copy of the message in form of byte array.
     *
     * @return a copy of the message in form of byte array.
     */
    public byte[] getMessageBytes() {
        return messageBytes.clone();
    }
}
