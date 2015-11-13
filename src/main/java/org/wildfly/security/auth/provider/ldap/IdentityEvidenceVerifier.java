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
package org.wildfly.security.auth.provider.ldap;

import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.auth.server.SupportLevel;
import org.wildfly.security.evidence.Evidence;

/**
 *
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
interface IdentityEvidenceVerifier {

    /**
     * Determine whether a given credential is definitely supported, possibly supported, or definitely not supported.
     *
     * @param evidenceType the evidence type (must not be {@code null})
     * @param algorithmName the algorithm name, if any
     * @return the level of support for this credential type
     * @throws RealmUnavailableException if the realm is unavailable to verify credentials.
     */
    SupportLevel getEvidenceVerifySupport(Class<? extends Evidence> evidenceType, String algorithmName) throws RealmUnavailableException;

    /**
     * Verify the given evidence against the named credential.
     *
     * @param evidence the evidence to verify.
     * @return {@code true} if the evidence is successfully verified, {@code false} otherwise.
     * @throws RealmUnavailableException if the realm is unavailable to verify credentials.
     */
    boolean verifyEvidence(final Evidence evidence) throws RealmUnavailableException;

}
