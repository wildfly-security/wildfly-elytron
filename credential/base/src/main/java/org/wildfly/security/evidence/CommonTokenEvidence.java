/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.evidence;

import org.wildfly.common.Assert;

public abstract class CommonTokenEvidence implements Evidence {

    private final String token;

    /**
     * Construct a new instance.
     *
     * @param token the bearer security token (must not be {@code null})
     */
    public CommonTokenEvidence(String token) {
        this.token = Assert.checkNotNullParam("token", token);
    }

    /**
     * Get security token.
     *
     * @return the security token
     */
    public String getToken() {
        return this.token;
    }

    /**
     * Returns the digital signature algorithm associated with
     * the designator for the cryptographic hash function.
     *
     * @param hashDesignator  designator for the cryptographic hash function
     * @return the corresponding digital signature algorithm; null when none found
     */
    public abstract String algorithmLookup (String hashDesignator);
}
