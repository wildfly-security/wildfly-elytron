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

public final class AnonymousPrincipal implements Principal, Serializable {

    private static final long serialVersionUID = -2539713938519809712L;

    private static final AnonymousPrincipal INSTANCE = new AnonymousPrincipal();

    public AnonymousPrincipal() {
    }

    public AnonymousPrincipal(String ignored) {
    }

    public static AnonymousPrincipal getInstance() {
        return INSTANCE;
    }

    public String getName() {
        return "anonymous";
    }

    public boolean equals(final Object o) {
        return o instanceof AnonymousPrincipal;
    }

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
