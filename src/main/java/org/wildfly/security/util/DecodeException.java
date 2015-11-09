/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2014 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.util;

/**
 * An exception which indicates that base 64 decoding has failed due to invalid or truncated input.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public class DecodeException extends IllegalArgumentException {

    private static final long serialVersionUID = 5823281980783313991L;

    /**
     * Constructs a new {@code DecodeException} instance.  The message is left blank ({@code null}), and no cause is
     * specified.
     */
    public DecodeException() {
    }

    /**
     * Constructs a new {@code DecodeException} instance with an initial message.  No cause is specified.
     *
     * @param msg the message
     */
    public DecodeException(final String msg) {
        super(msg);
    }

    /**
     * Constructs a new {@code DecodeException} instance with an initial cause.  If a non-{@code null} cause is
     * specified, its message is used to initialize the message of this {@code DecodeException}; otherwise the message
     * is left blank ({@code null}).
     *
     * @param cause the cause
     */
    public DecodeException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new {@code DecodeException} instance with an initial message and cause.
     *
     * @param msg the message
     * @param cause the cause
     */
    public DecodeException(final String msg, final Throwable cause) {
        super(msg, cause);
    }
}
