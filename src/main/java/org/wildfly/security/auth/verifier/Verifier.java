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

package org.wildfly.security.auth.verifier;

import java.util.Set;
import org.wildfly.security.auth.login.AuthenticationException;

/**
 * An entity which brings <em>evidence</em> to be checked with a credential, optionally yielding some kind of
 * <em>proof</em> that the evidence is sufficient to authenticate.  If the evidence is insufficient, an exception
 * is thrown.
 *
 * @param <P> the type of proof produced, or {@link Void} if none
 */
public abstract class Verifier<P> {

    /**
     * Get the set of credential types which can be used to perform verification.
     *
     * @return the credential type set
     */
    public abstract Set<Class<?>> getSupportedCredentialTypes();

    /**
     * Perform verification of this evidence against the given credential.  The credential will be of one of the
     * supported types from the set reported by {@link #getSupportedCredentialTypes()}.
     *
     * @param credential the credential against which to verify
     * @return the proof of verification, or {@code null} if there is no proof available
     * @throws AuthenticationException if the verification failed
     */
    public abstract P performVerification(Object credential) throws AuthenticationException;
}
