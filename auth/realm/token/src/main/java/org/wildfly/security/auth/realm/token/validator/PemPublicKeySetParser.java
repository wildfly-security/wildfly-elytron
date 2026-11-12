/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.auth.realm.token.validator;

import java.security.PublicKey;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;

import org.wildfly.common.iteration.CodePointIterator;
import org.wildfly.security.jose.jwks.JwksCache;
import org.wildfly.security.jose.jwks.JwksException;
import org.wildfly.security.jose.jwks.JwksKeySetParser;
import org.wildfly.security.pem.Pem;
import org.wildfly.security.pem.PemEntry;

/**
 * A {@link JwksKeySetParser} for the {@code publicKeyUrl} source: the response body is a single
 * PEM-encoded public key rather than a JWKS document.
 *
 * @author <a href="mailto:rojeda@redhat.com">Raul Ojeda Robles</a>
 */
final class PemPublicKeySetParser implements JwksKeySetParser {

    /**
     * Synthetic key id for the single key parsed from a PEM response. Retrieval always goes through
     * {@link JwksCache#getAnyKey(java.net.URL)}, which ignores {@code kid}, so this value is never
     * matched against anything.
     */
    private static final String SYNTHETIC_KID = "publicKeyUrl";

    static final PemPublicKeySetParser INSTANCE = new PemPublicKeySetParser();

    private PemPublicKeySetParser() {
    }

    @Override
    public Map<String, PublicKey> parse(byte[] rawBytes) throws JwksException {
        PublicKey publicKey;
        try {
            Iterator<PemEntry<?>> pemEntries = Pem.parsePemContent(CodePointIterator.ofUtf8Bytes(rawBytes));
            if (!pemEntries.hasNext()) {
                return Collections.emptyMap();
            }
            publicKey = pemEntries.next().tryCast(PublicKey.class);
        } catch (RuntimeException e) {
            throw new JwksException("Malformed PEM content", e);
        }

        if (publicKey == null) {
            // parsed fine, but the PEM block was the wrong type (certificate, private key, ...)
            return Collections.emptyMap();
        }

        Map<String, PublicKey> result = new LinkedHashMap<>();
        result.put(SYNTHETIC_KID, publicKey);
        return result;
    }
}
