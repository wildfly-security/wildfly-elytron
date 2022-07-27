/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2022 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.wildfly.security.auth.realm;

import java.io.IOException;

/**
 * Exception to indicate a general failure related to the Integrity Verification of the Filesystem Realm.
 *
 * @author <a href="mailto:araskar@redhat.com">Ashpan Raskar</a>
 */
public class IntegrityException extends IOException {


    private static final long serialVersionUID = 8889252552074803941L;

    /**
     * Constructs a new {@code IntegrityException} instance. The message is left blank ({@code null}), and no
     * cause is specified.
     */
    public IntegrityException() {
    }

    /**
     * Constructs a new {@code IntegrityException} instance with an initial message. No cause is specified.
     *
     * @param msg the message
     */
    public IntegrityException(final String msg) {
        super(msg);
    }

    /**
     * Constructs a new {@code IntegrityException} instance with an initial cause. If a non-{@code null} cause
     * is specified, its message is used to initialize the message of this {@code IntegrityException}; otherwise
     * the message is left blank ({@code null}).
     *
     * @param cause the cause
     */
    public IntegrityException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new {@code IntegrityException} instance with an initial message and cause.
     *
     * @param msg the message
     * @param cause the cause
     */
    public IntegrityException(final String msg, final Throwable cause) {
        super(msg, cause);
    }

}

