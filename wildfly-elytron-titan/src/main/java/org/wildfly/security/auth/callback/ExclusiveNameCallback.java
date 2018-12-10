/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016 Red Hat, Inc., and individual contributors
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

import javax.security.auth.callback.NameCallback;

/**
 * A variation on {@code NameCallback} which allows exclusive access to the backing identity to be requested.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public class ExclusiveNameCallback extends NameCallback implements ExtendedCallback {

    private static final long serialVersionUID = 3332866436399055886L;

    /**
     * @serial A flag indicating whether exclusive access to the backing identity is required.
     */
    private final boolean needsExclusiveAccess;

    /**
     * @serial A flag indicating whether exclusive access to the backing identity was granted.
     */
    private boolean exclusiveAccess;

    /**
     * @serial A flag indicating whether the callback is optional.
     */
    private final boolean optional;

    /**
     * Construct a new instance.
     *
     * @param prompt the text prompt (must not be {@code null})
     * @param needsExclusiveAccess {@code true} if exclusive access to the backing identity is required
     * @param optional {@code true} if the support for the callback is optional
     */
    public ExclusiveNameCallback(final String prompt, final boolean needsExclusiveAccess, final boolean optional) {
        super(prompt);
        this.needsExclusiveAccess = needsExclusiveAccess;
        this.optional = optional;
    }

    /**
     * Construct a new instance.
     *
     * @param prompt the text prompt (must not be {@code null})
     * @param defaultName the name to be used as the default name displayed with the prompt
     * @param needsExclusiveAccess {@code true} if exclusive access to the backing identity is required
     * @param optional {@code true} if the support for the callback is optional
     */
    public ExclusiveNameCallback(final String prompt, final String defaultName, final boolean needsExclusiveAccess, final boolean optional) {
        super(prompt, defaultName);
        this.needsExclusiveAccess = needsExclusiveAccess;
        this.optional = optional;
    }

    /**
     * Determine if exclusive access to the backing identity is required.
     *
     * @return {@code true} if exclusive access to the backing identity is required, {@code false} otherwise
     */
    public boolean needsExclusiveAccess() {
        return needsExclusiveAccess;
    }

    /**
     * Determine if exclusive access to the backing identity was granted.
     *
     * @return {@code true} if exclusive access to the backing identity was granted, {@code false} otherwise
     */
    public boolean hasExclusiveAccess() {
        return exclusiveAccess;
    }

    /**
     * Set whether exclusive access to the backing identity was granted.
     *
     * @param exclusiveAccess {@code true} if exclusive access to the backing identity was granted, {@code false} otherwise
     */
    public void setExclusiveAccess(final boolean exclusiveAccess) {
        this.exclusiveAccess = exclusiveAccess;
    }

    public boolean isOptional() {
        return optional;
    }

    public boolean needsInformation() {
        return true;
    }
}
