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

package org.wildfly.security.auth.server.event;

import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.authz.AuthorizationIdentity;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.evidence.Evidence;

/**
 * A realm event signifying authentication success.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class RealmSuccessfulAuthenticationEvent extends RealmDefiniteOutcomeAuthenticationEvent {
    private final AuthorizationIdentity authorizationIdentity;

    /**
     * Construct a new instance.
     *
     * @param realmIdentity the realm identity that successfully authenticated
     * @param authorizationIdentity the authenticated authorization identity
     * @param credentialName the name of the credential used (may be {@code null} if a credential was not used to authenticate)
     * @param credential the actual credential value from the authentication (may be {@code null} if not known)
     * @param evidence the evidence used to authenticate (may be {@code null} if not known or not applicable)
     */
    public RealmSuccessfulAuthenticationEvent(final RealmIdentity realmIdentity, final AuthorizationIdentity authorizationIdentity, final String credentialName, final Credential credential, final Evidence evidence) {
        super(realmIdentity, credentialName, credential, evidence);
        this.authorizationIdentity = authorizationIdentity;
    }

    /**
     * Get the authorization identity.
     *
     * @return the authorization identity
     */
    public AuthorizationIdentity getAuthorizationIdentity() {
        return authorizationIdentity;
    }

    public <P, R> R accept(final RealmEventVisitor<P, R> visitor, final P param) {
        return visitor.handleSuccessfulAuthenticationEvent(this, param);
    }

    public boolean isSuccess() {
        return true;
    }
}
