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

/**
 * The permission to run as another principal within some security domain.
 */
public final class RunAsPrincipalPermission extends Permission {

    private static final long serialVersionUID = -3361334389433669815L;

    public RunAsPrincipalPermission(final String name, final String securityDomainName) {
        super(compileName(name, securityDomainName));
    }

    private static String compileName(final String name, final String securityDomainName) {
        if (securityDomainName.indexOf(':') != -1) {
            throw new IllegalArgumentException("Security domain name is invalid");
        }
        return securityDomainName + ":" + name;
    }

    public boolean implies(final Permission permission) {
        return equals(permission);
    }

    public boolean equals(final Object obj) {
        return obj instanceof RunAsPrincipalPermission && equals((RunAsPrincipalPermission) obj);
    }

    public boolean equals(final RunAsPrincipalPermission perm) {
        return perm != null && perm.getName().equals(getName());
    }

    public int hashCode() {
        return getName().hashCode();
    }

    public String getActions() {
        return "";
    }
}
