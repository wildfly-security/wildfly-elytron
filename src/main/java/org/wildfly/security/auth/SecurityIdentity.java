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

package org.wildfly.security.auth;

import java.security.Permission;
import java.security.Principal;
import java.util.Collections;
import java.util.Set;
import java.util.prefs.Preferences;

/**
 * A distinct identity on a {@code IdentityContext}.  This may represent the identity of a {@code IdentityContext} when
 * used on a particular network connection or with a particular local resource.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public abstract class SecurityIdentity {
    private final Principal principal;

    protected SecurityIdentity(final Principal principal) {
        if (principal == null) {
            throw new IllegalArgumentException("principal is null");
        }
        this.principal = principal;
    }

    public final Principal getPrincipal() {
        return principal;
    }

    public final boolean equals(final Object obj) {
        return super.equals(obj);
    }

    public final int hashCode() {
        return super.hashCode();
    }

    @SuppressWarnings("CloneDoesntCallSuperClone")
    protected final Object clone() throws CloneNotSupportedException {
        throw new CloneNotSupportedException();
    }

    public boolean hasRole(String roleName) {
        return getRoles().contains(roleName);
    }

    public Set<String> getRoles() {
        return Collections.emptySet();
    }

    @SuppressWarnings("unused")
    public boolean checkPermission(Permission permission) {
        return false;
    }

    public Preferences getPreferences() {
        return null;
    }
}
