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
package org.wildfly.security.evidence;

/**
 * A piece of evidence that is comprised of a bearer security token.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public final class BearerTokenEvidence extends CommonTokenEvidence {

    /**
     * Construct a new instance.
     *
     * @param token the bearer security token (must not be {@code null})
     */
    public BearerTokenEvidence(String token) {
        super(token);
    }

    /**
     * Returns the digital signature algorithm associated with
     * the designator for the cryptographic hash function.
     *
     * Table for elliptic curves
     *         RS256 >> "SHA256withRSA"  SHA-256
     *         RS384 >> "SHA384withRSA"  SHA-384
     *         RS521 >> "SHA512withRSA"  SHA-512
     *
     * @param hashDesignator  designator for the cryptographic hash function
     * @return the corresponding digital signature algorithm; null when none found
     */
    @Override
    public String algorithmLookup (String hashDesignator) {
        switch (hashDesignator) {
            case "RS256":
                return "SHA256withRSA";
            case "RS384":
                return "SHA384withRSA";
            case "RS512":
                return "SHA512withRSA";
            default:
                return null;
        }
    }
}
