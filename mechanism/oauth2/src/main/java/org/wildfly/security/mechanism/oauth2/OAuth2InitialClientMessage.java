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
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class OAuth2InitialClientMessage {

    private final String auth;
    private final byte[] messageBytes;
    private final String authorizationId;

    public OAuth2InitialClientMessage(String authorizationId, String auth, byte[] messageBytes) {
        this.authorizationId = authorizationId;
        this.auth = auth;
        this.messageBytes = messageBytes;
    }

    public String getAuthorizationId() {
        return this.authorizationId;
    }

    public byte[] getMessage() {
        return this.messageBytes;
    }

    public String getAuth() {
        return auth;
    }

    public boolean isBearerToken() {
        return this.auth.startsWith("Bearer");
    }
}
