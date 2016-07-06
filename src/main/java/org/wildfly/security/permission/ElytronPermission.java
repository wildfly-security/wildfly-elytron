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

package org.wildfly.security.permission;

import org.wildfly.common.Assert;
import org.wildfly.security.util.StringEnumeration;
import org.wildfly.security.util.StringMapping;

/**
 * A general Elytron permission.  The permission {@code name} must be one of the following:
 * <ul>
 *     <li>{@code createAuthenticator}</li>
 *     <li>{@code createAuthenticationContextConfigurationClient}</li>
 *     <li>{@code createSecurityDomain}</li>
 * </ul>
 * The {@code actions} are not used and should be empty or {@code null}.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class ElytronPermission extends AbstractNameSetOnlyPermission<ElytronPermission> {

    private static final long serialVersionUID = 6124294238228442419L;

    private static final StringEnumeration strings = StringEnumeration.of(
        "createAuthenticator",
        "createAuthenticationContextConfigurationClient",
        "createSecurityDomain",
        "setRunAsPrincipal",
        "createServerAuthenticationContext",
        "getPrivateCredentials"
    );

    static final StringMapping<ElytronPermission> mapping = new StringMapping<>(strings, ElytronPermission::new);

    private static final ElytronPermission allPermission = new ElytronPermission("*");

    /**
     * Construct a new instance.
     *
     * @param name the name of the permission
     */
    public ElytronPermission(final String name) {
        this(name, null);
    }

    /**
     * Construct a new instance.
     *
     * @param name the name of the permission
     * @param actions the actions (should be empty)
     */
    public ElytronPermission(final String name, final String actions) {
        super(name, strings);
        requireEmptyActions(actions);
    }

    public ElytronPermission withName(final String name) {
        return forName(name);
    }

    /**
     * Get the permission with the given name.
     *
     * @param name the name (must not be {@code null})
     * @return the permission (not {@code null})
     * @throws IllegalArgumentException if the name is not valid
     */
    public static ElytronPermission forName(final String name) {
        Assert.checkNotNullParam("name", name);
        return name.equals("*") ? allPermission : mapping.getItemByString(name);
    }
}
