/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2015 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.auth.provider;

/**
 * The different support levels.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public enum SupportLevel {

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
