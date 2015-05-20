/*
 * JBoss, Home of Professional Open Source
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
package org.wildfly.security.storage;

import java.security.GeneralSecurityException;

/**
 * An exception indicating that given storage is not supporting particular {@link org.wildfly.security.password.Password} class.
 *
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>.
 */
public class UnsupportedPasswordClassException extends GeneralSecurityException {


    private static final long serialVersionUID = 5628800950499517909L;

    /**
     * Constructs a new {@code UnsupportedPasswordClassException} instance.  The message is left blank
     * ({@code null}), and no cause is specified.
     */
    public UnsupportedPasswordClassException() {
    }

    /**
     * Constructs a new {@code UnsupportedPasswordClassException} instance with an initial message.  No
     * cause is specified.
     *
     * @param msg the message
     */
    public UnsupportedPasswordClassException(String msg) {
        super(msg);
    }

    /**
     * Constructs a new {@code UnsupportedPasswordClassException} instance with an initial message and
     * cause.
     *
     * @param message the message
     * @param cause the cause
     */
    public UnsupportedPasswordClassException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * Constructs a new {@code UnsupportedPasswordClassException} instance with an initial cause.  If a
     * non-{@code null} cause is specified, its message is used to initialize the message of this {@code
     * Exception}; otherwise the message is left blank ({@code null}).
     *
     * @param cause the cause
     */
    public UnsupportedPasswordClassException(Throwable cause) {
        super(cause);
    }
}
