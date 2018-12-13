/*
 * JBoss, Home of Professional Open Source
 * Copyright 2013 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.auth.permission;

import org.wildfly.security.permission.AbstractNameOnlyPermission;

/**
 * The permission to run as another principal within some security domain.  Note that this permission is checked relative
 * to the security domain that the user is authenticated to.  The principal name is the effective name after all rewrite
 * operations have taken place.
 */
public final class RunAsPrincipalPermission extends AbstractNameOnlyPermission<RunAsPrincipalPermission> {

    private static final long serialVersionUID = -3361334389433669815L;

    /**
     * Construct a new instance.
     *
     * @param name the principal name, or {@code *} for global run-as permissions
     */
    public RunAsPrincipalPermission(final String name) {
        super(name);
    }

    /**
     * Construct a new instance.
     *
     * @param name the principal name, or {@code *} for global run-as permissions
     * @param ignored the permission actions (ignored)
     */
    public RunAsPrincipalPermission(final String name, @SuppressWarnings("unused") final String ignored) {
        this(name);
    }

    public RunAsPrincipalPermission withName(final String name) {
        return new RunAsPrincipalPermission(name);
    }
}
