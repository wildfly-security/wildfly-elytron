/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2018 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.x500.cert.acme;

import java.io.IOException;

/**
 * Exception to indicate a general failure related to the <a href="https://www.ietf.org/id/draft-ietf-acme-acme-14.txt">Automatic Certificate
 * Management Environment (ACME)</a> protocol.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 * @since 1.5.0
 */
public class AcmeException extends IOException {

    private static final long serialVersionUID = -1038330178933137221L;

    /**
     * Constructs a new {@code AcmeException} instance. The message is left blank ({@code null}), and no
     * cause is specified.
     */
    public AcmeException() {
    }

    /**
     * Constructs a new {@code AcmeException} instance with an initial message. No cause is specified.
     *
     * @param msg the message
     */
    public AcmeException(final String msg) {
        super(msg);
    }

    /**
     * Constructs a new {@code AcmeException} instance with an initial cause. If a non-{@code null} cause
     * is specified, its message is used to initialize the message of this {@code AcmeException}; otherwise
     * the message is left blank ({@code null}).
     *
     * @param cause the cause
     */
    public AcmeException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new {@code AcmeException} instance with an initial message and cause.
     *
     * @param msg the message
     * @param cause the cause
     */
    public AcmeException(final String msg, final Throwable cause) {
        super(msg, cause);
    }
}

