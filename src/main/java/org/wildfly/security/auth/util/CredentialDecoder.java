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

package org.wildfly.security.auth.util;

import java.security.Principal;

/**
 * A decoder which acquires a principal from a credential.  Implementations may indicate that the credential
 * is not understood.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public interface CredentialDecoder {

    /**
     * Get the principal from an opaque credential.  If this decoder cannot understand the given credential
     * type, {@code null} is returned.
     *
     * @param credential the credential to decode
     * @return the principal, or {@code null} if this decoder does not understand the credential
     */
    Principal getPrincipalFromCredential(Object credential);

    /**
     * Create an aggregated credential decoder.  The aggregated decoder will check each credential decoder until one
     * matches the credential; this result will be returned.
     *
     * @param decoders the constituent decoders
     * @return the aggregated decoder
     */
    static CredentialDecoder aggregate(final CredentialDecoder... decoders) {
        if (decoders == null) {
            throw new IllegalArgumentException("decoders is null");
        }
        return credential -> {
            Principal result;
            for (CredentialDecoder decoder : decoders) {
                result = decoder.getPrincipalFromCredential(credential);
                if (result != null) {
                    return result;
                }
            }
            return null;
        };
    }
}
