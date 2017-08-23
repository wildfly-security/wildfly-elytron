/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2017 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.auth.client;

import org.wildfly.security.auth.callback.ChannelBindingCallback;
import org.wildfly.security.auth.callback.CredentialCallback;
import org.wildfly.security.auth.callback.EvidenceVerifyCallback;
import org.wildfly.security.auth.callback.ParameterCallback;
import org.wildfly.security.auth.callback.PasswordResetCallback;
import org.wildfly.security.auth.callback.SSLCallback;
import org.wildfly.security.auth.callback.TrustedAuthoritiesCallback;

import java.util.EnumSet;

import javax.security.auth.callback.ChoiceCallback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.TextInputCallback;
import javax.security.auth.callback.TextOutputCallback;
import javax.security.sasl.RealmCallback;
import javax.security.sasl.RealmChoiceCallback;

/**
 * The kinds of callbacks which can be handled by the user's callback.
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public enum CallbackKind {
    /**
     * Callbacks which select a user name or principal: client side {@link NameCallback}
     */
    PRINCIPAL,
    /**
     * Callbacks which select a credential to use for authentication: {@link PasswordCallback} and {@link CredentialCallback}
     */
    CREDENTIAL,
    /**
     * Callbacks which handle local credential-reset requests: {@link PasswordResetCallback}
     */
    CREDENTIAL_RESET,
    /**
     * Callbacks which select the mechanism realm: {@link RealmChoiceCallback} and {@link RealmCallback}
     */
    REALM,
    /**
     * Callbacks which accept the peer's name or principal: server side {@link NameCallback}
     */
    PEER_PRINCIPAL,
    /**
     * Callbacks which handle or verify the peer's credentials: {@link EvidenceVerifyCallback}
     */
    PEER_CREDENTIAL,
    /**
     * Callbacks which extend {@link ChoiceCallback} (not including {@link RealmChoiceCallback}).
     */
    CHOICE,
    /**
     * Callbacks which select algorithm parameters to use for authentication: {@link ParameterCallback}
     */
    PARAMETERS,
    /**
     * Callbacks which accept the server's trusted authorities: {@link TrustedAuthoritiesCallback}
     */
    SERVER_TRUSTED_AUTHORITIES,
    /**
     * Callbacks which provide general output: {@link TextOutputCallback}
     */
    GENERAL_OUTPUT,
    /**
     * Callbacks which provide general input: {@link TextInputCallback}
     */
    GENERAL_INPUT,
    /**
     * Callbacks which deal with SSL configuration: {@link SSLCallback}
     */
    SSL,
    /**
     * Callbacks which configure channel binding options: {@link ChannelBindingCallback}
     */
    CHANNEL_BINDING,
    ;

    private static final int fullSize = values().length;

    /**
     * Determine whether the given set is fully populated (or "full"), meaning it contains all possible values.
     *
     * @param set the set
     * @return {@code true} if the set is full, {@code false} otherwise
     */
    public static boolean isFull(final EnumSet<CallbackKind> set) {
        return set != null && set.size() == fullSize;
    }

    /**
     * Determine whether this instance is equal to one of the given instances.
     *
     * @param v1 the first instance
     * @return {@code true} if one of the instances matches this one, {@code false} otherwise
     */
    public boolean in(final CallbackKind v1) {
        return this == v1;
    }

    /**
     * Determine whether this instance is equal to one of the given instances.
     *
     * @param v1 the first instance
     * @param v2 the second instance
     * @return {@code true} if one of the instances matches this one, {@code false} otherwise
     */
    public boolean in(final CallbackKind v1, final CallbackKind v2) {
        return this == v1 || this == v2;
    }

    /**
     * Determine whether this instance is equal to one of the given instances.
     *
     * @param v1 the first instance
     * @param v2 the second instance
     * @param v3 the third instance
     * @return {@code true} if one of the instances matches this one, {@code false} otherwise
     */
    public boolean in(final CallbackKind v1, final CallbackKind v2, final CallbackKind v3) {
        return this == v1 || this == v2 || this == v3;
    }

    /**
     * Determine whether this instance is equal to one of the given instances.
     *
     * @param values the possible values
     * @return {@code true} if one of the instances matches this one, {@code false} otherwise
     */
    public boolean in(final CallbackKind... values) {
        if (values != null) for (CallbackKind value : values) {
            if (this == value) return true;
        }
        return false;
    }
}
