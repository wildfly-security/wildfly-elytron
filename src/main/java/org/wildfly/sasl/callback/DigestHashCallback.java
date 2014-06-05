/*
 * JBoss, Home of Professional Open Source.
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

package org.wildfly.sasl.callback;

import javax.security.auth.callback.Callback;

import org.wildfly.sasl.util.HexConverter;

/**
 * Callback to allow Digest mechanisms to request the pre-digested {username : realm : password} value
 * instead of the plain text password.
 * <p/>
 * The benefit of this callback is that the server no longer needs to store the raw plain text password of the user.
 * <p/>
 * This Callback has accessor methods for both the raw byte[] of the hash and the hex encoded String of the hash,
 * however only one format of the hash should actually be set - the Callback will convert to the other format
 * should the get method be called.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class DigestHashCallback implements Callback {

    private String hexHash = null;
    private byte[] hash = null;

    /**
     * Construct the DigestHashCallback with the supplied prompt.
     *
     * @param prompt - the prompt.
     */
    public DigestHashCallback(final String prompt) {
    }

    /**
     * Get the hash that has been set on this Callback.
     * <p/>
     * If a Hex encoded hash has been it will be converted to the raw byte[] representation.
     *
     * @return the raw byte[] of the hash or null if no hash has been set.
     */
    public byte[] getHash() {
        if (hash == null && hexHash != null) {
            hash = HexConverter.convertFromHex(hexHash);  // Don't call set otherwise it will clear the hexHash
        }
        return hash;
    }

    /**
     * Get the hex encoded form of the hash set on this Callback.
     * <p/>
     * If a raw hash has been set it will be hex encoded before being returned.
     *
     * @return the hex encoded hash or null if no hash has been set.
     */
    public String getHexHash() {
        if (hexHash == null && hash != null) {
            hexHash = HexConverter.convertToHexString(hash); // Don't call set otherwise it will clear the hash
        }
        return hexHash;
    }

    /**
     * Sets the raw byte[] hash.
     * <p/>
     * If a hex encoded hash has been set it will be cleared.
     *
     * @param hash - the raw byte[] hash.
     */
    public void setHash(final byte[] hash) {
        this.hash = hash;
        this.hexHash = null;
    }

    /**
     * Sets the hex encoded form of a hash.
     * <p/>
     * If a raw hash has been set it will be cleared.
     *
     * @param hexHash - the hex encoded hash.
     */
    public void setHexHash(final String hexHash) {
        this.hexHash = hexHash;
        this.hash = null;
    }

}
