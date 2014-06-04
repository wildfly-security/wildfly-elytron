/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2011, Red Hat, Inc., and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
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
