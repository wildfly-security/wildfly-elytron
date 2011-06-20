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

import javax.security.auth.callback.Callback;

/**
 * A callback for a binary token.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class TokenCallback implements Callback {
    private final String prompt;
    private final int tokenLength;
    private byte[] token;

    /**
     * Construct a new instance.
     *
     * @param prompt the prompt
     * @param length the expected length of the token, in bytes
     */
    public TokenCallback(final String prompt, final int length) {
        this.prompt = prompt;
        tokenLength = length;
    }

    /**
     * Get the prompt.
     *
     * @return the prompt
     */
    public String getPrompt() {
        return prompt;
    }

    /**
     * Get the expected token length.
     *
     * @return the expected token length
     */
    public int getTokenLength() {
        return tokenLength;
    }

    /**
     * Get the token.
     *
     * @return the token
     */
    public byte[] getToken() {
        return token;
    }

    /**
     * Set the token.
     *
     * @param token the token
     */
    public void setToken(final byte[] token) {
        this.token = token.clone();
    }
}
