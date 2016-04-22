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
package org.wildfly.security.http;

import java.io.IOException;

/**
 * Exception to indicate a general failure with the HTTP authentication mechanism.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class HttpAuthenticationException extends IOException {

    /**
     * Constructs a new {@code HttpAuthenticationException}. The message is left blank ({@code null}),
     * and no cause is specified.
     */
    public HttpAuthenticationException() {
    }

    /**
     * Constructs a new {@code HttpAuthenticationException}. with the message provided,
     * and no cause is specified.
     *
     * @param message the message for this {@code HttpAuthenticationException}.
     */
    public HttpAuthenticationException(String message) {
        super(message);
    }

    /**
     * Constructs a new {@code HttpAuthenticationException} with an initial cause.
     *
     * @param cause the cause for this {@code HttpAuthenticationException}.
     */
    public HttpAuthenticationException(Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new {@code HttpAuthenticationException} with an initial message and cause.
     *
     * @param message the message for this {@code HttpAuthenticationException}.
     * @param cause the cause for this {@code HttpAuthenticationException}.
     */
    public HttpAuthenticationException(String message, Throwable cause) {
        super(message, cause);
    }

}
