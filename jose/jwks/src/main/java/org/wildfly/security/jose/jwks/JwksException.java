/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.jose.jwks;

/**
 * Checked exception thrown when a JWKS fetch operation fails.
 *
 * @author <a href="mailto:rojeda@redhat.com">Raul Ojeda Robles</a>
 */
public class JwksException extends Exception {

    public JwksException(String message) {
        super(message);
    }

    public JwksException(String message, Throwable cause) {
        super(message, cause);
    }
}
