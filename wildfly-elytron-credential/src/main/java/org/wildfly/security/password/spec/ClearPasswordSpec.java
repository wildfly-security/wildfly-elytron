/*
 * JBoss, Home of Professional Open Source
 * Copyright 2013 Red Hat, Inc., and individual contributors
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

import java.util.Arrays;

import org.wildfly.common.Assert;

/**
 * A password specification for clear passwords.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class ClearPasswordSpec implements PasswordSpec {

    private final char[] encodedPassword;

    /**
     * Construct a new instance.
     *
     * @param encodedPassword the password
     */
    public ClearPasswordSpec(final char[] encodedPassword) {
        Assert.checkNotNullParam("encodedPassword", encodedPassword);
        this.encodedPassword = encodedPassword;
    }

    /**
     * Get the password characters.
     *
     * @return the password characters
     */
    public char[] getEncodedPassword() {
        return encodedPassword;
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof ClearPasswordSpec && Arrays.equals(encodedPassword, ((ClearPasswordSpec)other).encodedPassword);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(encodedPassword);
    }
}
