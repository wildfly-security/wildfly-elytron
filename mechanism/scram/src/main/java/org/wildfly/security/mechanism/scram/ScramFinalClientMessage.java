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

import org.wildfly.security.password.interfaces.ScramDigestPassword;

/**
 * Final client message for the SCRAM authentication.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class ScramFinalClientMessage {

    private final ScramInitialClientMessage initialResponse;
    private final ScramInitialServerMessage initialChallenge;
    private final ScramDigestPassword password;
    private final byte[] clientProof;
    private final byte[] messageBytes;
    private final int proofOffset;

    /**
     * Constructs a new {@code ScramFinalClientMessage} instance.
     *
     * @param initialResponse the initial client message.
     * @param initialChallenge the initial server message.
     * @param password the password used for authentication.
     * @param clientProof the client proof sent to the server.
     * @param messageBytes the byte array of the message.
     * @param proofOffset the proof location in the {@code messageBytes}.
     */
    ScramFinalClientMessage(final ScramInitialClientMessage initialResponse, final ScramInitialServerMessage initialChallenge, final ScramDigestPassword password, final byte[] clientProof, final byte[] messageBytes, final int proofOffset) {
        this.initialResponse = initialResponse;
        this.initialChallenge = initialChallenge;
        this.password = password;
        this.clientProof = clientProof;
        this.messageBytes = messageBytes;
        this.proofOffset = proofOffset;
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
     * Returns the initial server message.
     *
     * @return the initial server message.
     */
    public ScramInitialServerMessage getInitialChallenge() {
        return initialChallenge;
    }

    /**
     * Returns the password used for authentication.
     *
     * @return the password used for authentication.
     */
    public ScramDigestPassword getPassword() {
        return password;
    }

    /**
     * Returns the client proof sent to the server.
     *
     * @return the client proof sent to the server.
     */
    byte[] getRawClientProof() {
        return clientProof;
    }

    /**
     * Returns the byte array of the message.
     *
     * @return the byte array of the message.
     */
    byte[] getRawMessageBytes() {
        return messageBytes;
    }

    /**
     * Returns a copy of the client proof sent to the server.
     *
     * @return a copy of the client proof sent to the server.
     */
    public byte[] getClientProof() {
        return clientProof.clone();
    }

    /**
     * Returns a copy of the byte array of the message.
     *
     * @return a copy of the byte array of the message.
     */
    public byte[] getMessageBytes() {
        return messageBytes.clone();
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
     * Returns the proof location in the message.
     *
     * @return the proof location in the message.
     */
    int getProofOffset() {
        return proofOffset;
    }
}
