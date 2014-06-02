/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2014, Red Hat, Inc., and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */

package org.jboss.sasl;

import javax.security.sasl.SaslException;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public class SaslAuthenticationInterruptedException extends SaslException {

    private static final long serialVersionUID = 3351228768569638601L;

    /**
     * Constructs a new {@code SaslAuthenticationInterruptedException} instance.  The message is left blank ({@code
     * null}), and no cause is specified.
     */
    public SaslAuthenticationInterruptedException() {
    }

    /**
     * Constructs a new {@code SaslAuthenticationInterruptedException} instance with an initial message.  No cause is
     * specified.
     *
     * @param msg the message
     */
    public SaslAuthenticationInterruptedException(final String msg) {
        super(msg);
    }

    /**
     * Constructs a new {@code SaslAuthenticationInterruptedException} instance with an initial cause.  If a non-{@code
     * null} cause is specified, its message is used to initialize the message of this {@code
     * SaslAuthenticationInterruptedException}; otherwise the message is left blank ({@code null}).
     *
     * @param cause the cause
     */
    public SaslAuthenticationInterruptedException(final Throwable cause) {
        super();
        initCause(cause);
    }

    /**
     * Constructs a new {@code SaslAuthenticationInterruptedException} instance with an initial message and cause.
     *
     * @param msg the message
     * @param cause the cause
     */
    public SaslAuthenticationInterruptedException(final String msg, final Throwable cause) {
        super(msg);
        initCause(cause);
    }
}
