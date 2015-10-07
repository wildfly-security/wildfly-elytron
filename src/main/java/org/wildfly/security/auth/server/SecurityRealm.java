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

package org.wildfly.security.auth.server;

import org.wildfly.common.Assert;
import org.wildfly.security._private.ElytronMessages;
import org.wildfly.security.auth.server.event.RealmEvent;

/**
 * A single authentication realm. A realm is backed by a single homogeneous store of identities and credentials.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public interface SecurityRealm {

    /**
     * For the given name create the {@link RealmIdentity} in the context of this security realm. Any validation / name
     * mapping is an implementation detail for the realm.
     * <p>
     * A realm returning a {@link RealmIdentity} does not confirm the existence of an identity, a realm may also return
     * {@code null} from this method if the provided {code name} can not be mapped to an identity although this is not required
     * of the realm.
     *
     * @param name the name to use when creating the {@link RealmIdentity}
     * @return the {@link RealmIdentity} for the provided {@code name} or {@code null}
     */
    RealmIdentity createRealmIdentity(String name) throws RealmUnavailableException;

    /**
     * Determine whether a given credential is definitely obtainable, possibly obtainable (for some identities),
     * or definitely not obtainable.
     *
     * @param credentialName the credential name
     * @return the level of support for this named credential
     * @throws RealmUnavailableException if the realm is not able to handle requests for any reason
     */
    SupportLevel getCredentialAcquireSupport(String credentialName) throws RealmUnavailableException;

    /**
     * Determine whether a given piece of evidence is definitely verifiable, possibly verifiable (for some identities),
     * or definitely not verifiable.
     *
     * @param credentialName the credential name the evidence would be verified against
     * @return the level of support for this named credential
     * @throws RealmUnavailableException if the realm is not able to handle requests for any reason
     */
    default SupportLevel getEvidenceVerifySupport(String credentialName) throws RealmUnavailableException {
        if (getCredentialAcquireSupport(credentialName) != SupportLevel.UNSUPPORTED) {
            return SupportLevel.POSSIBLY_SUPPORTED;
        }

        return SupportLevel.UNSUPPORTED;
    }

    /**
     * Handle a realm event.  These events allow the realm to act upon occurrences that are relevant to policy of
     * the realm; for example, the realm may choose to increase password iteration count on authentication success,
     * or change the salt of a password after a certain number of authentications.
     * <p>
     * The default implementation does nothing.
     *
     * @param event the realm event
     */
    default void handleRealmEvent(RealmEvent event) {}

    /**
     * Safely pass an event to a security realm, absorbing and logging any exception that occurs.
     *
     * @param realm the security realm to notify (not {@code null})
     * @param event the event to send (not {@code null})
     */
    static void safeHandleRealmEvent(SecurityRealm realm, RealmEvent event) {
        Assert.checkNotNullParam("realm", realm);
        Assert.checkNotNullParam("event", event);
        try {
            realm.handleRealmEvent(event);
        } catch (Throwable t) {
            ElytronMessages.log.eventHandlerFailed(t);
        }
    }

    /**
     * An empty security realm.
     */
    SecurityRealm EMPTY_REALM = new SecurityRealm() {
        public RealmIdentity createRealmIdentity(final String name) throws RealmUnavailableException {
            return RealmIdentity.NON_EXISTENT;
        }

        public SupportLevel getCredentialAcquireSupport(final String credentialName) throws RealmUnavailableException {
            return SupportLevel.UNSUPPORTED;
        }

        public SupportLevel getEvidenceVerifySupport(final String credentialName) throws RealmUnavailableException {
            return SupportLevel.UNSUPPORTED;
        }
    };
}
