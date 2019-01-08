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

package org.wildfly.security.mechanism;

import java.nio.charset.StandardCharsets;
import java.util.EnumSet;
import java.util.Locale;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public enum ScramServerErrorCode {
    INVALID_ENCODING,
    EXTENSIONS_NOT_SUPPORTED,
    INVALID_PROOF,
    CHANNEL_BINDINGS_DONT_MATCH,
    SERVER_DOES_NOT_SUPPORT_CHANNEL_BINDING,
    SERVER_DOES_SUPPORT_CHANNEL_BINDING,
    CHANNEL_BINDING_NOT_SUPPORTED,
    CHANNEL_BINDING_NOT_PROVIDED,
    UNSUPPORTED_CHANNEL_BINDING_TYPE,
    UNKNOWN_USER,
    INVALID_USERNAME_ENCODING,
    NO_RESOURCES,
    OTHER_ERROR,
    ;

    private final String text;
    private final byte[] messageBytes;

    ScramServerErrorCode() {
        text = name().replace('_', '-').toLowerCase(Locale.US);
        final int length = text.length();
        byte[] msg = new byte[length + 2];
        msg[0] = 'e'; msg[1] = '=';
        System.arraycopy(text.getBytes(StandardCharsets.UTF_8), 0, msg, 2, length);
        messageBytes = msg;
    }

    public String getText() {
        return text;
    }

    public byte[] getMessageBytes() {
        return messageBytes.clone();
    }

    byte[] getRawMessageBytes() {
        return messageBytes;
    }

    public static ScramServerErrorCode fromErrorString(String value) {
        try {
            return valueOf(value.replace('-', '_').toUpperCase(Locale.US));
        } catch (IllegalArgumentException ignored) {
            return OTHER_ERROR;
        }
    }

    private static final int fullSize = values().length;

    /**
     * Determine whether the given set is fully populated (or "full"), meaning it contains all possible values.
     *
     * @param set the set
     *
     * @return {@code true} if the set is full, {@code false} otherwise
     */
    public static boolean isFull(final EnumSet<ScramServerErrorCode> set) {
        return set != null && set.size() == fullSize;
    }

    /**
     * Determine whether this instance is equal to one of the given instances.
     *
     * @param v1 the first instance
     *
     * @return {@code true} if one of the instances matches this one, {@code false} otherwise
     */
    public boolean in(final ScramServerErrorCode v1) {
        return this == v1;
    }

    /**
     * Determine whether this instance is equal to one of the given instances.
     *
     * @param v1 the first instance
     * @param v2 the second instance
     *
     * @return {@code true} if one of the instances matches this one, {@code false} otherwise
     */
    public boolean in(final ScramServerErrorCode v1, final ScramServerErrorCode v2) {
        return this == v1 || this == v2;
    }

    /**
     * Determine whether this instance is equal to one of the given instances.
     *
     * @param v1 the first instance
     * @param v2 the second instance
     * @param v3 the third instance
     *
     * @return {@code true} if one of the instances matches this one, {@code false} otherwise
     */
    public boolean in(final ScramServerErrorCode v1, final ScramServerErrorCode v2, final ScramServerErrorCode v3) {
        return this == v1 || this == v2 || this == v3;
    }

    /**
     * Determine whether this instance is equal to one of the given instances.
     *
     * @param values the possible values
     *
     * @return {@code true} if one of the instances matches this one, {@code false} otherwise
     */
    public boolean in(final ScramServerErrorCode... values) {
        if (values != null) for (ScramServerErrorCode value : values) {
            if (this == value) return true;
        }
        return false;
    }
}
