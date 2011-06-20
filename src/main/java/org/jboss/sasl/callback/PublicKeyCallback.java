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

package org.jboss.sasl.callback;

import java.security.PublicKey;

import javax.security.auth.callback.Callback;

/**
 * Callback to retrieve or provide a public key during authentication.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class PublicKeyCallback implements Callback {
    private final String prompt;
    private final String[] algorithmNames;
    private PublicKey publicKey;

    /**
     * Construct a new instance.
     *
     * @param prompt the prompt string
     * @param algorithmNames the algorithm names to accept
     */
    public PublicKeyCallback(final String prompt, final String[] algorithmNames) {
        this.prompt = prompt;
        this.algorithmNames = algorithmNames;
    }

    /**
     * Construct a new instance.
     *
     * @param prompt the prompt string
     * @param publicKey the public key value
     * @param algorithmNames the algorithm names to accept
     */
    public PublicKeyCallback(final String prompt, final PublicKey publicKey, final String[] algorithmNames) {
        this.prompt = prompt;
        this.publicKey = publicKey;
        this.algorithmNames = algorithmNames;
    }

    /**
     * Get the prompt string.
     *
     * @return the prompt string
     */
    public String getPrompt() {
        return prompt;
    }

    /**
     * Get the public key.
     *
     * @return the public key
     */
    public PublicKey getPublicKey() {
        return publicKey;
    }

    /**
     * Set the public key.
     *
     * @param publicKey the public key
     */
    public void setPublicKey(final PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    /**
     * Get the acceptable algorithm names.
     *
     * @return the algorithm names
     */
    public String[] getAlgorithmNames() {
        return algorithmNames.clone();
    }

    /**
     * Convenience method to determine whether an algorithm name is allowed.
     *
     * @param name the algorithm name
     * @return {@code true} if the algorithm is allowed
     */
    public boolean allows(String name) {
        for (String algorithmName : algorithmNames) {
            if (algorithmName.equals(name)) {
                return true;
            }
        }
        return false;
    }
}
