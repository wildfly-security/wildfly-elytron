/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2014, Red Hat, Inc., and individual contributors
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

package org.wildfly.security.auth.provider;

/**
 * The level of support for a type of credential.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public enum CredentialSupport {
    /**
     * The given credential type is definitely not supported.
     */
    UNSUPPORTED,
    /**
     * The given credential type may be supported.
     */
    POSSIBLY_SUPPORTED,
    /**
     * The given credential type is definitely supported.
     */
    SUPPORTED,
    ;

    /**
     * Determine if this object represents definite support.
     *
     * @return {@code true} if this object represents definite support, {@code false} otherwise
     */
    public boolean isDefinitelySupported() {
        return this == SUPPORTED;
    }

    /**
     * Determine if this object represents possible <em>or</em> definite support.
     *
     * @return {@code true} if this object represents possible <em>or</em> definite support, {@code false} otherwise
     */
    public boolean mayBeSupported() {
        return this != UNSUPPORTED;
    }

    /**
     * Determine if this object represents definite lack of support.
     *
     * @return {@code true} if this object represents definite lack of support, {@code false} otherwise
     */
    public boolean isNotSupported() {
        return this == UNSUPPORTED;
    }
}
