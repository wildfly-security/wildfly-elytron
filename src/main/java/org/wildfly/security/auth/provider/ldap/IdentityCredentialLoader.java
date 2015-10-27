/*
 * JBoss, Home of Professional Open Source
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

package org.wildfly.security.auth.provider.ldap;

import org.wildfly.security.auth.server.SupportLevel;
import org.wildfly.security.credential.Credential;

/**
 * A {@link CredentialLoader} for loading credentials stored in LDAP directory.
 *
 * Implementations of this interface are instantiated for a specific identity, as a result all of the methods on this interface
 * are specific to that identity.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
interface IdentityCredentialLoader {

    /**
     * Determine whether a given credential is definitely supported, possibly supported, or definitely not supported.
     *
     * @param credentialName the credential name to check
     * @return the level of support for this credential type
     */
    SupportLevel getCredentialSupport(String credentialName);

    /**
     * Acquire a credential of the given type.
     *
     * @param <C> the type to which should be credential casted
     * @param credentialName the name of the credential
     * @param credentialType the class of type to which should be credential casted
     * @return the credential, or {@code null} if the principal has no credential of that name or cannot be casted to that type
     */
    <C extends Credential> C getCredential(String credentialName, Class<C> credentialType);
}
