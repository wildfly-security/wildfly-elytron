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

package org.wildfly.security.auth.login;

import org.wildfly.security.auth.IdentityContext;

/**
 *
 */
public interface ClientAuthentication extends AutoCloseable {

    /**
     * Add the result of this authentication to an existing identity context, returning a new identity context.
     *
     * @param existing the existing context
     * @return the combined context
     */
    IdentityContext combine(IdentityContext existing);

    /**
     * Combine the result of this authentication with the current identity context, returning a new identity context.
     *
     * @return the combined context
     */
    IdentityContext combine();

    /**
     * Terminate this authentication.  Identity contexts using this authentication
     * may no longer function after this method is called.
     */
    void close();
}
