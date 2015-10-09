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
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class ScramFinalClientMessage {

    private final ScramInitialClientMessage initialResponse;
    private final ScramInitialServerMessage initialChallenge;
    private final ScramDigestPassword password;
    private final byte[] clientProof;
    private final byte[] messageBytes;
    private final int proofOffset;

    ScramFinalClientMessage(final ScramInitialClientMessage initialResponse, final ScramInitialServerMessage initialChallenge, final ScramDigestPassword password, final byte[] clientProof, final byte[] messageBytes, final int proofOffset) {
        this.initialResponse = initialResponse;
        this.initialChallenge = initialChallenge;
        this.password = password;
        this.clientProof = clientProof;
        this.messageBytes = messageBytes;
        this.proofOffset = proofOffset;
    }

    public ScramInitialClientMessage getInitialResponse() {
        return initialResponse;
    }

    public ScramInitialServerMessage getInitialChallenge() {
        return initialChallenge;
    }

    public ScramDigestPassword getPassword() {
        return password;
    }

    byte[] getRawClientProof() {
        return clientProof;
    }

    byte[] getRawMessageBytes() {
        return messageBytes;
    }

    public byte[] getClientProof() {
        return clientProof.clone();
    }

    public byte[] getMessageBytes() {
        return messageBytes.clone();
    }

    public ScramMechanism getMechanism() {
        return initialResponse.getMechanism();
    }

    int getProofOffset() {
        return proofOffset;
    }
}
