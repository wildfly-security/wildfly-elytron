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

import java.io.IOException;

import javax.security.sasl.SaslException;

import org.wildfly.common.Assert;
import org.wildfly.security.http.HttpAuthenticationException;

/**
 * A network authentication mechanism exception.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public class AuthenticationMechanismException extends IOException {
    private static final long serialVersionUID = -436234128057297342L;

    /**
     * Constructs a new {@code AuthenticationMechanismException} instance.  The message is left blank ({@code null}),
     * and no cause is specified.
     */
    public AuthenticationMechanismException() {
    }

    /**
     * Constructs a new {@code AuthenticationMechanismException} instance with an initial message.  No cause is
     * specified.
     *
     * @param msg the message
     */
    public AuthenticationMechanismException(final String msg) {
        super(msg);
    }

    /**
     * Constructs a new {@code AuthenticationMechanismException} instance with an initial cause.  If a non-{@code null}
     * cause is specified, its message is used to initialize the message of this {@code
     * AuthenticationMechanismException}; otherwise the message is left blank ({@code null}).
     *
     * @param cause the cause
     */
    public AuthenticationMechanismException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new {@code AuthenticationMechanismException} instance with an initial message and cause.
     *
     * @param msg the message
     * @param cause the cause
     */
    public AuthenticationMechanismException(final String msg, final Throwable cause) {
        super(msg, cause);
    }

    /**
     * Convert this exception to a SASL exception with the same message and stack trace.
     *
     * @return the SASL exception
     */
    public SaslException toSaslException() {
        return copyContents(this, new SaslException(getMessage(), getCause()));
    }

    /**
     * Convert this exception to an HTTP exception with the same message and stack trace.
     *
     * @return the HTTP exception
     */
    public HttpAuthenticationException toHttpAuthenticationException() {
        return copyContents(this, new HttpAuthenticationException(getMessage(), getCause()));
    }

    /**
     * Convert the given exception to an {@code AuthenticationMechanismException}.  If the given exception is
     * already a {@code AuthenticationMechanismException}, it is returned as-is.
     *
     * @param source the source exception (must not be {@code null})
     * @return the new exception instance (not {@code null})
     */
    public static AuthenticationMechanismException fromException(final Exception source) {
        Assert.checkNotNullParam("source", source);
        if (source instanceof AuthenticationMechanismException) return (AuthenticationMechanismException) source;
        return copyContents(source, new AuthenticationMechanismException(source.getMessage(), source.getCause()));
    }

    private static <T extends Throwable> T copyContents(final Exception source, final T throwable) {
        throwable.setStackTrace(source.getStackTrace());
        final Throwable[] suppressed = source.getSuppressed();
        if (suppressed != null) for (final Throwable t : suppressed) {
            throwable.addSuppressed(t);
        }
        return throwable;
    }
}
