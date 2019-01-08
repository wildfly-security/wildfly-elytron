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

import java.security.Permission;
import java.security.Principal;

import org.wildfly.common.Assert;

/**
 * An exception indicating that an identity authorization check has failed.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public class AuthorizationCheckException extends AuthorizationException {

    private static final long serialVersionUID = 5010607869851804099L;

    private final Permission failedPermission;

    /**
     * Constructs a new {@code AuthorizationException} instance with an initial message.  No cause is specified.
     *
     * @param msg the message
     * @param authorizationPrincipal the principal that failed the authorization check
     * @param failedPermission the permission that failed the authorization check
     */
    public AuthorizationCheckException(final String msg, final Principal authorizationPrincipal, final Permission failedPermission) {
        super(msg, authorizationPrincipal);
        Assert.checkNotNullParam("failedPermission", failedPermission);
        this.failedPermission = failedPermission;
    }

    /**
     * Constructs a new {@code AuthorizationException} instance with an initial message and cause.
     *
     * @param msg the message
     * @param cause the cause
     * @param authorizationPrincipal the principal that failed the authorization check
     * @param failedPermission the permission that failed the authorization check
     */
    public AuthorizationCheckException(final String msg, final Throwable cause, final Principal authorizationPrincipal, final Permission failedPermission) {
        super(msg, cause, authorizationPrincipal);
        Assert.checkNotNullParam("failedPermission", failedPermission);
        this.failedPermission = failedPermission;
    }

    /**
     * Get the permission that failed the authorization check.
     *
     * @return the permission that failed the authorization check
     */
    public Permission getFailedPermission() {
        return failedPermission;
    }
}
