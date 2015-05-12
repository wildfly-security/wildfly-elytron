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

package org.wildfly.security.auth.principal;

import java.io.Serializable;
import java.security.Principal;

/**
 * The singleton anonymous principal.
 */
public final class AnonymousPrincipal implements Principal, Serializable {

    private static final long serialVersionUID = -2539713938519809712L;

    private static final AnonymousPrincipal INSTANCE = new AnonymousPrincipal();

    /**
     * Construct a new instance (should not be used; call {@link #getInstance()} instead).
     */
    public AnonymousPrincipal() {
    }

    /**
     * Construct a new instance (should not be used; call {@link #getInstance()} instead).
     *
     * @param ignored ignored
     */
    public AnonymousPrincipal(String ignored) {
    }

    /**
     * Get the anonymous principal instance.
     *
     * @return the anonymous principal instance
     */
    public static AnonymousPrincipal getInstance() {
        return INSTANCE;
    }

    /**
     * Get the principal name (always "anonymous").
     *
     * @return the principal name (always "anonymous")
     */
    public String getName() {
        return "anonymous";
    }

    /**
     * Determine whether the given object is also an anonymous principal.
     *
     * @param o the other object
     * @return {@code true} if the object is an anonymous principal, {@code false} otherwise
     */
    public boolean equals(final Object o) {
        return o instanceof AnonymousPrincipal;
    }

    /**
     * Get the hash code of this principal.
     *
     * @return the hash code of this principal
     */
    public int hashCode() {
        return 3;
    }

    Object writeReplace() {
        return INSTANCE;
    }

    Object readResolve() {
        return INSTANCE;
    }
}
