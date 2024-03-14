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

/**
 * Represents the initial client message for OAuth2 protocol.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class OAuth2InitialClientMessage {

    private final String auth;
    private final byte[] messageBytes;
    private final String authorizationId;

    /**
     * Constructs a new {@code OAuth2InitialClientMessage} instance.
     *
     * @param authorizationId the ID of the user to be authorized.
     * @param auth the authorization information in form of a String.
     * @param messageBytes the byte array containing the message.
     */
    public OAuth2InitialClientMessage(String authorizationId, String auth, byte[] messageBytes) {
        this.authorizationId = authorizationId;
        this.auth = auth;
        this.messageBytes = messageBytes;
    }

    /**
     * Returns the ID of the user to be authorized.
     *
     * @return the ID of the user to be authorized.
     */
    public String getAuthorizationId() {
        return this.authorizationId;
    }

    /**
     * Returns the byte array containing the message.
     *
     * @return the byte array containing the message.
     */
    public byte[] getMessage() {
        return this.messageBytes;
    }

    /**
     * Returns the authorization information in form of a String.
     *
     * @return the authorization information in form of a String.
     */
    public String getAuth() {
        return auth;
    }

    /**
     * Returns whether the client provides a Bearer token.
     *
     * @return {@code True} if the authorization information contains "Bearer", {@code false} otherwise.
     */
    public boolean isBearerToken() {
        return this.auth.startsWith("Bearer");
    }
}
