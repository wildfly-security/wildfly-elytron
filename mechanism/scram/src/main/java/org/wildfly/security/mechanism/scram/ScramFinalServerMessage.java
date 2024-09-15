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
 * Final server message for the SCRAM authentication.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class ScramFinalServerMessage {
    private final byte[] serverSignature;
    private final byte[] messageBytes;

    /**
     * Constructs a new {@code ScramFinalServerMessage} instance.
     *
     * @param serverSignature the server signature sent to the client in form of the byte array.
     * @param messageBytes the final server message in form of byte array.
     */
    ScramFinalServerMessage(final byte[] serverSignature, final byte[] messageBytes) {
        this.serverSignature = serverSignature;
        this.messageBytes = messageBytes;
    }

    /**
     * Returns the server signature sent to the client in form of the byte array.
     *
     * @return the server signature sent to the client in form of the byte array.
     */
    byte[] getRawServerSignature() {
        return serverSignature;
    }

    /**
     * Returns the final server message in form of byte array.
     *
     * @return the final server message in form of byte array.
     */
    byte[] getRawMessageBytes() {
        return messageBytes;
    }

    /**
     * Returns a copy of the server signature sent to the client in form of the byte array.
     *
     * @return a copy of the server signature sent to the client in form of the byte array.
     */
    public byte[] getServerSignature() {
        return serverSignature.clone();
    }

    /**
     * Returns a copy of the final server message in form of byte array.
     *
     * @return a copy of the final server message in form of byte array.
     */
    public byte[] getMessageBytes() {
        return messageBytes.clone();
    }
}
