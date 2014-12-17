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
package org.wildfly.security.password.impl;

import org.wildfly.security.password.interfaces.DigestMD5Password;
import org.wildfly.security.password.spec.DigestMD5PasswordSpec;
import org.wildfly.security.sasl.digest._private.DigestMD5Utils;
import org.wildfly.security.sasl.util.Charsets;

import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;

/**
 * Pre-digested (DigestMD5) credential type implementation.
 *
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>.
 */
class DigestMD5PasswordImpl extends AbstractPasswordImpl implements DigestMD5Password {

    static final long serialVersionUID = 9129555139213387660L;

    private final byte[] hA1;
    private final byte[] nonce;
    private final int nonceCount;
    private final byte[] cnonce;
    private final String authzid;
    private final String qop;
    private final String digestURI;
    private final byte[] digestResponse;
    private final boolean utf8Encoded;

    DigestMD5PasswordImpl(byte[] clonedHA1, byte[] clonedNonce, int nonceCount, byte[] clonedCnonce, String authzid, String qop, String digestURI, boolean utf8Encoded) {
        this.hA1 = clonedHA1;
        this.nonce = clonedNonce;
        this.nonceCount = nonceCount;
        this.cnonce = clonedCnonce;
        this.authzid = authzid;
        this.qop = qop;
        this.digestURI = digestURI;
        this.utf8Encoded = utf8Encoded;
        this.digestResponse = DigestMD5Utils.digestResponse(hA1, nonce, nonceCount, cnonce, authzid, qop, digestURI);
    }

    DigestMD5PasswordImpl(byte[] clonedHA1, byte[] clonedNonce, int nonceCount, byte[] clonedCnonce, String authzid, String qop, String digestURI) {
        this(clonedHA1, clonedNonce, nonceCount, clonedCnonce, authzid, qop, digestURI, Boolean.FALSE);
    }

    DigestMD5PasswordImpl(DigestMD5PasswordSpec spec, byte[] hA1) {
        this(hA1.clone(), spec.getNonce().clone(), spec.getNonceCount(), spec.getCnonce().clone(), spec.getAuthzid(), spec.getQop(), spec.getDigestURI(), spec.isUtf8Encoded());
    }

    @Override
    <S extends KeySpec> S getKeySpec(Class<S> keySpecType) throws InvalidKeySpecException {
        return null;
    }

    @Override
    boolean verify(char[] guess) throws InvalidKeyException {
        if (guess == null) {
            throw new InvalidKeyException("Guess cannot be null");
        }
        byte[] guessedHashA1 = (utf8Encoded ? new String(guess).getBytes(Charsets.UTF_8) : new String(guess).getBytes(Charsets.LATIN_1));
        return verify(guessedHashA1);
    }

    boolean verify(byte[] guess) {
        byte[] guessBasedResponse = DigestMD5Utils.digestResponse(guess, nonce, nonceCount, cnonce, authzid, qop, digestURI);
        try {
            return Arrays.equals(digestResponse, guessBasedResponse);
        } catch (NullPointerException e) {
            throw new IllegalStateException("digestResponse cannot be null");
        }
    }

    @Override
    <T extends KeySpec> boolean convertibleTo(Class<T> keySpecType) {
        return false;
    }

    @Override
    public String getAlgorithm() {
        return ALGORITHM_DIGEST_MD5;
    }

    @Override
    public String getFormat() {
        return null;
    }

    @Override
    public byte[] getEncoded() {
        return new byte[0];
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

    public byte[] getDigestResponse() {
        return digestResponse;
    }

    public boolean isUtf8Encoded() {
        return utf8Encoded;
    }

}
