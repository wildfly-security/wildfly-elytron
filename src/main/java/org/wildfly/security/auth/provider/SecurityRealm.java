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

package org.wildfly.security.auth.provider;

import java.security.Principal;


/**
 * A single authentication realm. A realm is backed by a single homogeneous store of identities and credentials.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public interface SecurityRealm {

    /**
     * For the given name create the {@link RealmIdentity} in the context of this security realm.
     *
     * Any validation / name mapping is an implementation detail for the realm.
     *
     * A realm returning a {@link RealmIdentity} does not confirm the existence of an identity, a realm may also return
     * {@code null} from this method if the provided {code name} can not be mapped to an identity although this is not required
     * of the realm.
     *
     * @param name The name to use when creating the {@link RealmIdentity}
     * @return The {@link RealmIdentity} for the provided {@code name} or {@code null}
     */
    RealmIdentity createRealmIdentity(String name);

    /**
     * Create a {@link RealmIdentity} from an existing {@link Principal}.
     *
     * TODO - Not entirely convinced we need this yet,
     *
     * @param principal The principal to use to create the {@link RealmIdentity}
     * @return The {@link RealmIdentity} for the provided {@code principal} or {@code null}
     */
    RealmIdentity createRealmIdentity(Principal principal);

    /**
     * Determine whether a given credential is definitely supported, possibly supported (for some identities), or definitely not
     * supported.
     *
     * @param credentialType the credential type
     * @return the level of support for this credential type
     */
    CredentialSupport getCredentialSupport(Class<?> credentialType);

}
