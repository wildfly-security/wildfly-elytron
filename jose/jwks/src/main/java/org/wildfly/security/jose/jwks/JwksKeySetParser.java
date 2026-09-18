/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.jose.jwks;

import java.io.IOException;
import java.security.PublicKey;
import java.util.Map;

/**
 * Pluggable strategy for turning a raw fetched response body into the set of keys a {@link JwksCache}
 * entry should cache, keyed by {@code kid}.
 *
 * @author <a href="mailto:rojeda@redhat.com">Raul Ojeda Robles</a>
 */
@FunctionalInterface
public interface JwksKeySetParser {

    /**
     * Parse the raw response body into a {@code kid -> PublicKey} map.
     *
     * @param rawBytes the raw response body
     * @return the parsed keys, keyed by {@code kid} (never {@code null}, may be empty)
     * @throws JwksException if the content cannot be parsed
     * @throws IOException if the content cannot be parsed
     */
    Map<String, PublicKey> parse(byte[] rawBytes) throws JwksException, IOException;
}
