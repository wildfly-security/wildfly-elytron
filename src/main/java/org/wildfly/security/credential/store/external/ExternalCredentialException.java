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
package org.wildfly.security.credential.store.external;

/**
 * An exception indicating that operation with {@code SecurityVault} has failed.
 *
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>.
 */
public class ExternalCredentialException extends Exception {


    private static final long serialVersionUID = 6464213521763358276L;

    /**
     * Constructs a new {@code ExternalCredentialException} instance.  The message is left blank
     * ({@code null}), and no cause is specified.
     */
    public ExternalCredentialException() {
    }

    /**
     * Constructs a new {@code ExternalCredentialException} instance with an initial message.  No
     * cause is specified.
     *
     * @param msg the message
     */
    public ExternalCredentialException(String msg) {
        super(msg);
    }

    /**
     * Constructs a new {@code ExternalCredentialException} instance with an initial message and
     * cause.
     *
     * @param message the message
     * @param cause the cause
     */
    public ExternalCredentialException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * Constructs a new {@code ExternalCredentialException} instance with an initial cause.  If a
     * non-{@code null} cause is specified, its message is used to initialize the message of this {@code
     * Exception}; otherwise the message is left blank ({@code null}).
     *
     * @param cause the cause
     */
    public ExternalCredentialException(Throwable cause) {
        super(cause);
    }
}
