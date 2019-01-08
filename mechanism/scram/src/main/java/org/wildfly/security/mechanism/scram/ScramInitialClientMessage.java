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

import java.util.Arrays;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class ScramInitialClientMessage {
    private final ScramMechanism mechanism;
    private final String authorizationId;
    private final String authenticationName;
    private final boolean binding;
    private final String bindingType;
    private final byte[] bindingData;
    private final byte[] nonce;
    private final int initialPartIndex;
    private final byte[] messageBytes;

    ScramInitialClientMessage(final ScramClient scramClient, final String authenticationName, final boolean binding, final byte[] nonce, final int initialPartIndex, final byte[] messageBytes) {
        this.binding = binding;
        this.initialPartIndex = initialPartIndex;
        bindingType = scramClient.getBindingType();
        bindingData = scramClient.getRawBindingData();
        mechanism = scramClient.getMechanism();
        authorizationId = scramClient.getAuthorizationId();
        this.authenticationName = authenticationName;
        this.nonce = nonce;
        this.messageBytes = messageBytes;
    }

    ScramInitialClientMessage(final ScramMechanism mechanism, final String authorizationId, final String authenticationName, final boolean binding, final String bindingType, final byte[] bindingData, final byte[] nonce, final int initialPartIndex, final byte[] messageBytes) {
        this.mechanism = mechanism;
        this.authorizationId = authorizationId;
        this.authenticationName = authenticationName;
        this.binding = binding;
        this.bindingType = bindingType;
        this.bindingData = bindingData;
        this.nonce = nonce;
        this.initialPartIndex = initialPartIndex;
        this.messageBytes = messageBytes;
    }

    public ScramMechanism getMechanism() {
        return mechanism;
    }

    public String getAuthenticationName() {
        return authenticationName;
    }

    public byte[] getNonce() {
        return nonce.clone();
    }

    byte[] getRawNonce() {
        return nonce;
    }

    public byte[] getInitialPart() {
        return Arrays.copyOfRange(messageBytes, 0, initialPartIndex);
    }

    public byte[] getMessageBytes() {
        return messageBytes.clone();
    }

    public String getAuthorizationId() {
        return authorizationId;
    }

    public boolean isBinding() {
        return binding;
    }

    public String getBindingType() {
        return bindingType;
    }

    public byte[] getBindingData() {
        return bindingData == null ? null : bindingData.clone();
    }

    byte[] getRawBindingData() {
        return bindingData;
    }

    int getInitialPartIndex() {
        return initialPartIndex;
    }

    byte[] getRawMessageBytes() {
        return messageBytes;
    }
}
