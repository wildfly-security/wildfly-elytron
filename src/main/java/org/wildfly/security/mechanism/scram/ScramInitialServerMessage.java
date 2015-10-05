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
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class ScramInitialServerMessage {
    private final ScramInitialClientMessage initialResponse;
    private final byte[] serverNonce;
    private final byte[] salt;
    private final int iterationCount;
    private final byte[] messageBytes;

    ScramInitialServerMessage(final ScramInitialClientMessage initialResponse, final byte[] serverNonce, final byte[] salt, final int iterationCount, final byte[] messageBytes) {
        this.initialResponse = initialResponse;
        this.serverNonce = serverNonce;
        this.salt = salt;
        this.iterationCount = iterationCount;
        this.messageBytes = messageBytes;
    }

    public ScramMechanism getMechanism() {
        return initialResponse.getMechanism();
    }

    public ScramInitialClientMessage getInitialResponse() {
        return initialResponse;
    }

    public byte[] getServerNonce() {
        return serverNonce.clone();
    }

    byte[] getRawServerNonce() {
        return serverNonce;
    }

    public int getIterationCount() {
        return iterationCount;
    }

    byte[] getRawSalt() {
        return salt;
    }

    byte[] getRawMessageBytes() {
        return messageBytes;
    }

    public byte[] getSalt() {
        return salt.clone();
    }

    public byte[] getMessageBytes() {
        return messageBytes.clone();
    }
}
