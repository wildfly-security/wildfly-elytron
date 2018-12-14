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

import org.wildfly.common.Assert;
import org.wildfly.security.mechanism.AuthenticationMechanismException;

/**
 * A SCRAM server-side exception with an error code.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public class ScramServerException extends AuthenticationMechanismException {
    private static final long serialVersionUID = 5410786267588390307L;

    private final ScramServerErrorCode error;

    /**
     * Constructs a new {@code ScramServerException} instance.  The message is left blank ({@code null}), and no cause
     * is specified.
     *
     * @param error the server error code
     */
    public ScramServerException(final ScramServerErrorCode error) {
        Assert.checkNotNullParam("error", error);
        this.error = error;
    }

    /**
     * Constructs a new {@code ScramServerException} instance with an initial message.  No cause is specified.
     *
     * @param msg the message
     * @param error the server error code
     */
    public ScramServerException(final String msg, final ScramServerErrorCode error) {
        super(msg);
        Assert.checkNotNullParam("error", error);
        this.error = error;
    }

    /**
     * Constructs a new {@code ScramServerException} instance with an initial cause.  If a non-{@code null} cause is
     * specified, its message is used to initialize the message of this {@code ScramServerException}; otherwise the
     * message is left blank ({@code null}).
     *
     * @param cause the cause
     * @param error the server error code
     */
    public ScramServerException(final Throwable cause, final ScramServerErrorCode error) {
        super(cause);
        Assert.checkNotNullParam("error", error);
        this.error = error;
    }

    /**
     * Constructs a new {@code ScramServerException} instance with an initial message and cause.
     *  @param msg the message
     * @param cause the cause
     * @param error the server error code
     */
    public ScramServerException(final String msg, final Throwable cause, final ScramServerErrorCode error) {
        super(msg, cause);
        Assert.checkNotNullParam("error", error);
        this.error = error;
    }

    public String getMessage() {
        return super.getMessage() + ": " + error.getText();
    }

    public ScramServerErrorCode getError() {
        return error;
    }
}
