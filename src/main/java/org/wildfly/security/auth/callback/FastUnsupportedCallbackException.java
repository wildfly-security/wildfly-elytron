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

package org.wildfly.security.auth.callback;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;

/**
 * A version of {@code UnsupportedCallbackException} which does not initialize a full stack trace, and thus is much
 * more efficient to construct.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public class FastUnsupportedCallbackException extends UnsupportedCallbackException {

    private static final long serialVersionUID = -990072831042809709L;

    private static final StackTraceElement[] NO_STACK = new StackTraceElement[0];

    /**
     * Constructs a new {@code FastUnsupportedCallbackException} instance.  The message is left blank ({@code null}),
     * and no cause is specified.
     *
     * @param callback the callback which is not supported (should not be {@code null})
     */
    public FastUnsupportedCallbackException(final Callback callback) {
        super(callback);
    }

    /**
     * Constructs a new {@code FastUnsupportedCallbackException} instance with an initial message.  No cause is
     * specified.
     *
     * @param callback the callback which is not supported (should not be {@code null})
     * @param msg the message
     */
    public FastUnsupportedCallbackException(final Callback callback, final String msg) {
        super(callback, msg);
    }

    /**
     * Does nothing but return this instance.
     *
     * @param cause ignored
     * @return this instance
     */
    public Throwable initCause(final Throwable cause) {
        return this;
    }

    /**
     * Returns an empty stack.
     *
     * @return an empty stack
     */
    public StackTraceElement[] getStackTrace() {
        return NO_STACK;
    }

    /**
     * Does nothing but return this instance.
     *
     * @return this instance
     */
    public Throwable fillInStackTrace() {
        return this;
    }

    /**
     * Does nothing.
     *
     * @param stackTrace ignored
     */
    public void setStackTrace(final StackTraceElement[] stackTrace) {
    }
}
