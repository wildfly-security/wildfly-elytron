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
import java.util.Collections;

import org.wildfly.common.Assert;
import org.wildfly.security._private.ElytronMessages;
import org.wildfly.security.authz.Attributes;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.evidence.Evidence;

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

    default void updateCredential(Credential credential) throws RealmUnavailableException {
        // todo: Need a way to just replace a single credential instead
        setCredentials(Collections.singletonList(credential));
    }

    /**
     * Modify the attributes collection of this identity.  If the identity does not exist, an exception is thrown.
     *
     * @param attributes the new attributes collection
     * @throws RealmUnavailableException if updating the attributes collection fails for some reason
     */
    void setAttributes(Attributes attributes) throws RealmUnavailableException;

    /**
     * A modifiable identity for a non-existent user who cannot be created.
     */
    ModifiableRealmIdentity NON_EXISTENT = new ModifiableRealmIdentity() {
        public SupportLevel getCredentialAcquireSupport(final Class<? extends Credential> credentialType, final String algorithmName) throws RealmUnavailableException {
            Assert.checkNotNullParam("credentialType", credentialType);
            return SupportLevel.UNSUPPORTED;
        }

        public SupportLevel getEvidenceVerifySupport(final Class<? extends Evidence> evidenceType, final String algorithmName) throws RealmUnavailableException {
            Assert.checkNotNullParam("evidenceType", evidenceType);
            return SupportLevel.UNSUPPORTED;
        }

        public <C extends Credential> C getCredential(final Class<C> credentialType) throws RealmUnavailableException {
            Assert.checkNotNullParam("credentialType", credentialType);
            return null;
        }

        public boolean verifyEvidence(final Evidence evidence) throws RealmUnavailableException {
            Assert.checkNotNullParam("evidence", evidence);
            return false;
        }

        public boolean exists() throws RealmUnavailableException {
            return false;
        }

        public void delete() throws RealmUnavailableException {
            // no operation
        }

        public void create() throws RealmUnavailableException {
            throw ElytronMessages.log.unableToCreateIdentity();
        }

        public void setCredentials(final Collection<? extends Credential> credentials) throws RealmUnavailableException {
            throw ElytronMessages.log.noSuchIdentity();
        }

        public void setAttributes(final Attributes attributes) throws RealmUnavailableException {
            throw ElytronMessages.log.noSuchIdentity();
        }
    };
}
