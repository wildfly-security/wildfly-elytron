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

package org.wildfly.security.auth.server;

import java.util.Collection;

import org.wildfly.security.authz.Attributes;
import org.wildfly.security.credential.Credential;

/**
 * A realm identity which is modifiable.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public interface ModifiableRealmIdentity extends RealmIdentity {

    /**
     * Delete this realm identity.  After this call, {@link #exists()} will return {@code false}.  If the identity
     * does not exist, an exception is thrown.
     *
     * @throws RealmUnavailableException if deletion fails for some reason
     */
    void delete() throws RealmUnavailableException;

    /**
     * Create this realm identity.  After this call, {@link #exists()} will return {@code true} and the credentials
     * and role sets will be empty.  If the identity already exists, an exception is thrown.
     *
     * @throws RealmUnavailableException if creation fails for some reason
     */
    void create() throws RealmUnavailableException;

    /**
     * Set the credentials of this identity.  If the identity does not exist, an exception is thrown.
     * Any existing credential(s) are replaced/updated with the new value (in a possibly realm-specific manner).
     *
     * @param credentials the new credentials to set
     * @throws RealmUnavailableException if updating the credentials fails for some reason
     */
    void setCredentials(Collection<? extends Credential> credentials) throws RealmUnavailableException;

    /**
     * Modify the attributes collection of this identity.  If the identity does not exist, an exception is thrown.
     *
     * @param attributes the new attributes collection
     * @throws RealmUnavailableException if updating the attributes collection fails for some reason
     */
    void setAttributes(Attributes attributes) throws RealmUnavailableException;
}
