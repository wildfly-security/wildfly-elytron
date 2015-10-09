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

/**
 * An exception indicating that an authorization check failed for reasons not related to the actual authorization of
 * the identity.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public class AuthorizationFailureException extends AuthorizationException {
    private static final long serialVersionUID = - 5699181816026435025L;

    /**
     * Constructs a new {@code AuthorizationFailureException} instance with an initial message.  No cause is specified.
     *
     * @param msg the message
     * @param authorizationPrincipal the principal being authorized
     */
    public AuthorizationFailureException(final String msg, final Principal authorizationPrincipal) {
        super(msg, authorizationPrincipal);
    }

    /**
     * Constructs a new {@code AuthorizationFailureException} instance with an initial message and cause.
     *
     * @param msg the message
     * @param cause the cause
     * @param authorizationPrincipal the principal being authorized
     */
    public AuthorizationFailureException(final String msg, final Throwable cause, final Principal authorizationPrincipal) {
        super(msg, cause, authorizationPrincipal);
    }
}
