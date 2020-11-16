/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2020 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.http.oidc;

import java.io.IOException;

/**
 * Exception to indicate a general failure related to the OpenID Connect HTTP mechanism.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 * @since 1.14.0
 */
public class OidcException extends IOException {

    private static final long serialVersionUID = -7618442108721988521L;

    /**
     * Constructs a new {@code OidcException} instance. The message is left blank ({@code null}), and no
     * cause is specified.
     */
    public OidcException() {
    }

    /**
     * Constructs a new {@code OidcException} instance with an initial message. No cause is specified.
     *
     * @param msg the message
     */
    public OidcException(final String msg) {
        super(msg);
    }

    /**
     * Constructs a new {@code OidcException} instance with an initial cause. If a non-{@code null} cause
     * is specified, its message is used to initialize the message of this {@code OidcException}; otherwise
     * the message is left blank ({@code null}).
     *
     * @param cause the cause
     */
    public OidcException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new {@code OidcException} instance with an initial message and cause.
     *
     * @param msg the message
     * @param cause the cause
     */
    public OidcException(final String msg, final Throwable cause) {
        super(msg, cause);
    }

}
