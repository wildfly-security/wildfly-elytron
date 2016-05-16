/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.auth.realm.token;

import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.authz.Attributes;
import org.wildfly.security.evidence.BearerTokenEvidence;

/**
 * <p>A {@link TokenValidator} is responsible to validate a {@link BearerTokenEvidence} and support validation and transformation
 * of different types of security tokens.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public interface TokenValidator {

    /**
     * <p>Validates a {@link BearerTokenEvidence} and returns an {@link Attributes} instance containing all information
     * within a security token passed through <code>evidence</code>.
     *
     * @param evidence a {@link BearerTokenEvidence} holding the security token to validate
     * @return an {@link Attributes} instance containing all information from the security token, when valid. Otherwise,
     * this method returns null to indicate that the security token is invalid
     * @throws RealmUnavailableException if any error occurs when validating the evidence
     */
    Attributes validate(BearerTokenEvidence evidence) throws RealmUnavailableException;
}
