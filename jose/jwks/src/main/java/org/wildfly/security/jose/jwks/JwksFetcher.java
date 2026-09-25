/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.jose.jwks;

import java.net.URL;

/**
 * HTTP transport abstraction for fetching a JWKS document from a remote endpoint.
 *
 * @author <a href="mailto:rojeda@redhat.com">Raul Ojeda Robles</a>
 */
@FunctionalInterface
public interface JwksFetcher {

    /**
     * Default cap on the size of a fetched response body.
     */
    long DEFAULT_MAX_RESPONSE_SIZE_BYTES = 262_144; // 256 KB

    /**
     * Fetch the JWKS document from the given URL.
     *
     * @param url the JWKS endpoint URL
     * @return the raw response body as bytes (expected to be a JSON JWKS document)
     * @throws JwksException if the fetch fails for any reason (I/O error, non-200 status, etc.)
     */
    byte[] fetch(URL url) throws JwksException;
}
