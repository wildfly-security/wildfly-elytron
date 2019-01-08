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

package org.wildfly.security.permission;

/**
 * An exception which is thrown when an invalid permission class is instantiated.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public class InvalidPermissionClassException extends IllegalArgumentException {
    private static final long serialVersionUID = 7910334218992625018L;

    /**
     * Constructs a new {@code InvalidPermissionClassException} instance.  The message is left blank ({@code null}), and
     * no
     * cause is specified.
     */
    public InvalidPermissionClassException() {
    }

    /**
     * Constructs a new {@code InvalidPermissionClassException} instance with an initial message.  No
     * cause is specified.
     *
     * @param msg the message
     */
    public InvalidPermissionClassException(final String msg) {
        super(msg);
    }

    /**
     * Constructs a new {@code InvalidPermissionClassException} instance with an initial cause.  If
     * a non-{@code null} cause is specified, its message is used to initialize the message of this
     * {@code InvalidPermissionClassException}; otherwise the message is left blank ({@code null}).
     *
     * @param cause the cause
     */
    public InvalidPermissionClassException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new {@code InvalidPermissionClassException} instance with an initial message and cause.
     *
     * @param msg the message
     * @param cause the cause
     */
    public InvalidPermissionClassException(final String msg, final Throwable cause) {
        super(msg, cause);
    }
}
