/*
 * JBoss, Home of Professional Open Source
 * Copyright 2014 Red Hat, Inc., and individual contributors
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
package org.wildfly.security.password.spec;

/**
 * A {@link PasswordSpec} for a password represented by a Digest Response as seen in DigestMD5 SASL mechanism.
 *
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>
 */
public class DigestMD5PasswordSpec implements PasswordSpec {

    private final byte[] hA1;
    private final byte[] nonce;
    private final int nonceCount;
    private final byte[] cnonce;
    private final String authzid;
    private final String qop;
    private final String digestURI;
    private final boolean utf8Encoded;

    public DigestMD5PasswordSpec(byte[] hA1, byte[] nonce, int nonceCount, byte[] cnonce, String authzid, String qop, String digestURI, boolean utf8Encoded) {
        this.hA1 = hA1;
        this.nonce = nonce;
        this.nonceCount = nonceCount;
        this.cnonce = cnonce;
        this.authzid = authzid;
        this.qop = qop;
        this.digestURI = digestURI;
        this.utf8Encoded = utf8Encoded;
    }

    public byte[] getHA1() {
        return hA1;
    }

    public byte[] getNonce() {
        return nonce;
    }

    public int getNonceCount() {
        return nonceCount;
    }

    public byte[] getCnonce() {
        return cnonce;
    }

    public String getAuthzid() {
        return authzid;
    }

    public String getQop() {
        return qop;
    }

    public String getDigestURI() {
        return digestURI;
    }

    public boolean isUtf8Encoded() {
        return utf8Encoded;
    }
}
