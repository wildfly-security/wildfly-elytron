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

package org.wildfly.security.authz;

import java.security.Principal;

import org.wildfly.common.Assert;

/**
 * A general authorization exception.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public abstract class AuthorizationException extends SecurityException {
    private static final long serialVersionUID = 3791176860282223771L;

    private final Principal authorizationPrincipal;

    /**
     * Constructs a new {@code AuthorizationException} instance with an initial message.  No cause is specified.
     *
     * @param msg the message
     * @param authorizationPrincipal the principal being authorized
     */
    protected AuthorizationException(final String msg, final Principal authorizationPrincipal) {
        super(msg);
        Assert.checkNotNullParam("authorizationPrincipal", authorizationPrincipal);
        this.authorizationPrincipal = authorizationPrincipal;
    }

    /**
     * Constructs a new {@code AuthorizationException} instance with an initial message and cause.
     *
     * @param msg the message
     * @param cause the cause
     * @param authorizationPrincipal the principal being authorized
     */
    protected AuthorizationException(final String msg, final Throwable cause, final Principal authorizationPrincipal) {
        super(msg, cause);
        Assert.checkNotNullParam("authorizationPrincipal", authorizationPrincipal);
        this.authorizationPrincipal = authorizationPrincipal;
    }

    /**
     * Get the principal being authorized.
     *
     * @return the principal being authorized
     */
    public Principal getAuthorizationPrincipal() {
        return authorizationPrincipal;
    }
}
