/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.auth;

import java.util.EnumSet;

import org.wildfly.common.Assert;

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

    private static final int fullSize = values().length;

    /**
     * Determine whether the given set is fully populated (or "full"), meaning it contains all possible values.
     *
     * @param set the set
     *
     * @return {@code true} if the set is full, {@code false} otherwise
     */
    public static boolean isFull(final EnumSet<SupportLevel> set) {
        return set != null && set.size() == fullSize;
    }

    /**
     * Determine whether this instance is equal to one of the given instances.
     *
     * @param v1 the first instance
     *
     * @return {@code true} if one of the instances matches this one, {@code false} otherwise
     */
    public boolean in(final SupportLevel v1) {
        return this == v1;
    }

    /**
     * Determine whether this instance is equal to one of the given instances.
     *
     * @param v1 the first instance
     * @param v2 the second instance
     *
     * @return {@code true} if one of the instances matches this one, {@code false} otherwise
     */
    public boolean in(final SupportLevel v1, final SupportLevel v2) {
        return this == v1 || this == v2;
    }

    /**
     * Determine whether this instance is equal to one of the given instances.
     *
     * @param v1 the first instance
     * @param v2 the second instance
     * @param v3 the third instance
     *
     * @return {@code true} if one of the instances matches this one, {@code false} otherwise
     */
    public boolean in(final SupportLevel v1, final SupportLevel v2, final SupportLevel v3) {
        return this == v1 || this == v2 || this == v3;
    }

    /**
     * Determine whether this instance is equal to one of the given instances.
     *
     * @param values the possible values
     *
     * @return {@code true} if one of the instances matches this one, {@code false} otherwise
     */
    public boolean in(final SupportLevel... values) {
        if (values != null) for (SupportLevel value : values) {
            if (this == value) return true;
        }
        return false;
    }

    /**
     * Get the maximum support level between two candidates.
     *
     * @param o1 the first support level (must not be {@code null})
     * @param o2 the second support level (must not be {@code null})
     * @return the maximum support level (not {@code null})
     */
    public static SupportLevel max(SupportLevel o1, SupportLevel o2) {
        Assert.checkNotNullParam("o1", o1);
        Assert.checkNotNullParam("o2", o2);
        return o1.compareTo(o2) < 0 ? o2 : o1;
    }
}
