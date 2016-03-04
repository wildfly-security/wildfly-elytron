/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2015 Red Hat, Inc., and individual contributors
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

import org.wildfly.security.permission.AbstractBooleanPermission;

/**
 * Establish whether the current identity has permission to complete an authentication ("log in").
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class LoginPermission extends AbstractBooleanPermission<LoginPermission> {

    private static final long serialVersionUID = - 5776174571770792690L;

    /**
     * Construct a new instance.
     */
    public LoginPermission() {
    }

    /**
     * Construct a new instance.
     *
     * @param name ignored
     */
    public LoginPermission(@SuppressWarnings("unused") final String name) {
    }

    /**
     * Construct a new instance.
     *
     * @param name ignored
     * @param actions ignored
     */
    public LoginPermission(@SuppressWarnings("unused") final String name, @SuppressWarnings("unused") final String actions) {
    }
}
