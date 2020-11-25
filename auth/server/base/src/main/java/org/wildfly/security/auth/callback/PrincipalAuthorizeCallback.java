/*
 * Copyright 2020 Red Hat, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wildfly.security.auth.callback;

import java.security.Principal;
import org.wildfly.common.Assert;
import org.wildfly.security.auth.principal.NamePrincipal;

/**
 * <p>An authorization callback similar to javase {@link javax.security.sasl.AuthorizeCallback}
 * but using a generic principal.</p>
 *
 * @author rmartinc
 */
public class PrincipalAuthorizeCallback implements ExtendedCallback {

    private final Principal principal;
    private boolean authorized;

    /**
     * Creates a new instance to authorize the associated <code>name</code>.
     * It will be transformed in a {@link NamePrincipal}.
     *
     * @param name the name to authorize
     */
    public PrincipalAuthorizeCallback(String name) {
        Assert.checkNotNullParam("name", name);
        this.principal = new NamePrincipal(name);
    }

    /**
     * Creates a new instance to authorize the associated <code>principal</code>.
     *
     * @param principal the principal to authorize
     */
    public PrincipalAuthorizeCallback(Principal principal) {
        Assert.checkNotNullParam("principal", principal);
        this.principal = principal;
    }

    /**
     * Indicates if the principal was successfully authorized.
     *
     * @return true if the principal was successfully authorized. Otherwise, false
     */
    public boolean isAuthorized() {
        return authorized;
    }

    /**
     * Sets whether the authorization is allowed for the principal.
     *
     * @param authorized authorization result
     */
    public void setAuthorized(boolean authorized) {
        this.authorized = authorized;
    }

    /**
     * Returns the {@link Principal}.
     *
     * @return the principal (not {@code null})
     */
    public Principal getPrincipal() {
        return this.principal;
    }
}
