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

import java.io.Serializable;

/**
 * An optional callback indicating the success or failure of the authentication operation.  When this callback is
 * received, the callback handler may free any resources that were required to perform the authentication.  This
 * callback should always be sent to the callback handler last.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class AuthenticationCompleteCallback implements ExtendedCallback, Serializable {

    private static final long serialVersionUID = -8336218311376736914L;

    public static final AuthenticationCompleteCallback SUCCEEDED = new AuthenticationCompleteCallback(true);

    public static final AuthenticationCompleteCallback FAILED = new AuthenticationCompleteCallback(false);

    /**
     * @serial The flag indicating whether the authentication was successful.
     */
    private final boolean success;

    /**
     * Construct a new instance.
     *
     * @param success {@code true} if the authentication was successful, {@code false} otherwise
     */
    private AuthenticationCompleteCallback(final boolean success) {
        this.success = success;
    }

    /**
     * Determine whether authentication succeeded.  Always returns the opposite of {@link #failed()}.
     *
     * @return {@code true} if authentication succeeded, {@code false} otherwise
     */
    public boolean succeeded() {
        return success;
    }

    /**
     * Determine whether authentication failed.  Always returns the opposite of {@link #succeeded()}.
     *
     * @return {@code true} if the authentication failed, {@code false} otherwise
     */
    public boolean failed() {
        return ! success;
    }
}
