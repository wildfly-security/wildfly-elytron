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

import java.security.Permission;

public final class SecurityDomainPermission extends Permission {

    private static final long serialVersionUID = 8533735187740371169L;

    private final int actions;

    public SecurityDomainPermission(final String name, final Action... actions) {
        super(name);
        int i = 0;
        for (Action action : actions) {
            i |= action.i;
        }
        this.actions = i;
    }

    public boolean implies(final Permission permission) {
        // xxx blah blah
        return false;
    }

    public boolean equals(final Object obj) {
        return false;
    }

    public int hashCode() {
        return 0;
    }

    public String getActions() {
        return null;
    }

    enum Action {
        CREATE(1),
        ACCESS(2),
        ;

        private final int i;
        Action(final int i) {
            this.i = i;
        }
    }
}
