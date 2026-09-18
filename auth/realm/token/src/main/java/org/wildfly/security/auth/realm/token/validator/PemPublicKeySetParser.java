/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.auth.realm.token.validator;

import org.wildfly.common.iteration.CodePointIterator;
import org.wildfly.security.jose.jwks.JwksCache;
import org.wildfly.security.jose.jwks.JwksException;
import org.wildfly.security.jose.jwks.JwksKeySetParser;
import org.wildfly.security.pem.Pem;
import org.wildfly.security.pem.PemEntry;

import java.security.PublicKey;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * A {@link JwksKeySetParser} for the {@code publicKeyUrl} source: the response body is a single
 * PEM-encoded public key rather than a JWKS document.
 *
 * <p>An empty or content-free response, or a PEM block of the wrong type (a certificate or private key
 * instead of a public key), is treated as "no usable key" — an empty map, not an exception — so it falls
 * through to whatever fallback the caller has configured (e.g. an inline default key), exactly like a
 * JWKS document containing no matching key would. Malformed PEM content (a {@code -----BEGIN} block that
 * fails to parse) is wrapped as a {@link JwksException}, so {@link JwksCache} treats it like any other
 * fetch failure — logged, subject to {@code preserveStaleOnFailure}, and never propagated as an exception
 * to the caller.
 *
 * @author <a href="mailto:rojeda@redhat.com">Raul Ojeda Robles</a>
 */
final class PemPublicKeySetParser implements JwksKeySetParser {

    /**
     * Synthetic key id for the single key parsed from a PEM response. Retrieval always goes through
     * {@link JwksCache#getAnyKey(java.net.URL)}, which ignores {@code kid}, so this value is never
     * matched against anything — it only exists because {@link JwksCache} caches by a
     * {@code kid -> PublicKey} map internally.
     */
    private static final String SYNTHETIC_KID = "publicKeyUrl";

    static final PemPublicKeySetParser INSTANCE = new PemPublicKeySetParser();

    private PemPublicKeySetParser() {
    }

    @Override
    public Map<String, PublicKey> parse(byte[] rawBytes) throws JwksException {
        Iterator<PemEntry<?>> pemEntries = Pem.parsePemContent(CodePointIterator.ofUtf8Bytes(rawBytes));

        boolean hasEntry;
        try {
            hasEntry = pemEntries.hasNext();
        } catch (IllegalArgumentException e) {
            throw new JwksException("Malformed PEM content", e);
        }
        if (!hasEntry) {
            return Collections.emptyMap();
        }

        PublicKey publicKey = pemEntries.next().tryCast(PublicKey.class);
        if (publicKey == null) {
            // parsed fine, but the PEM block was the wrong type (certificate, private key, ...)
            return Collections.emptyMap();
        }

        Map<String, PublicKey> result = new LinkedHashMap<>();
        result.put(SYNTHETIC_KID, publicKey);
        return result;
    }
}
