/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2024 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.encryption.client;

/**
 * An exception thrown to indicate that the encryption client
 * configuration is invalid.  Examine the cause for more information
 * about the problem.
 *
 * @author <a href="mailto:prpaul@redhat.com">Prarthona Paul</a>
 */
public class InvalidEncryptionClientConfigurationException extends IllegalArgumentException {
    private static final long serialVersionUID = -6795326356890031539L;


    /**
     * Constructs a new {@code InvalidEncryptedExpressionConfigurationException} instance.  The message is left blank ({@code
     * null}), and no cause is specified.
     */
    public InvalidEncryptionClientConfigurationException() {
    }

    /**
     * Constructs a new {@code InvalidAuthenticationConfigurationException} instance with an initial cause.  If a
     * non-{@code null} cause is specified, its message is used to initialize the message of this {@code
     * InvalidAuthenticationConfigurationException}; otherwise the message is left blank ({@code null}).
     *
     * @param cause the cause
     */
    public InvalidEncryptionClientConfigurationException(final String cause) {
        super(cause);
    }


    /**
     * Constructs a new {@code InvalidAuthenticationConfigurationException} instance with an initial cause.  If a
     * non-{@code null} cause is specified, its message is used to initialize the message of this {@code
     * InvalidAuthenticationConfigurationException}; otherwise the message is left blank ({@code null}).
     *
     * @param cause the cause
     */
    public InvalidEncryptionClientConfigurationException(final Throwable cause) {
        super(cause);
    }
}
