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

package org.wildfly.security.evidence;

import java.security.Principal;
import java.util.function.Function;

/**
 * A piece of evidence which may be used for credential verification.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public interface Evidence {

    /**
     * Get the {@link Principal} which can be derived from this evidence, this can be {@code null} if there is no derived Principal.
     *
     * @return the {@link Principal} which can be derived from this evidence, this can be {@code null} if there is no derived Principal.
     */
    default Principal getPrincipal() {
        return null;
    }

    /**
     * Cast this evidence type if the type and algorithm matches.
     *
     * @param evidenceType the evidence type class to check
     * @param algorithmName the name of the algorithm or {@code null} if any algorithm is acceptable
     * @param <E> the evidence type
     * @return the evidence cast as the target type, or {@code null} if the evidence does not match the criteria
     */
    default <E> E castAs(Class<E> evidenceType, String algorithmName) {
        return castAndApply(evidenceType, algorithmName, Function.identity());
    }

    /**
     * Cast this evidence type if the type matches.
     *
     * @param evidenceType the evidence type class to check
     * @param <E> the evidence type
     * @return the evidence cast as the target type, or {@code null} if the evidence does not match the criteria
     */
    default <E> E castAs(Class<E> evidenceType) {
        return castAndApply(evidenceType, Function.identity());
    }

    /**
     * Cast this evidence type and apply a function if the type matches.
     *
     * @param evidenceType the evidence type class to check
     * @param algorithmName the name of the algorithm or {@code null} if any algorithm is acceptable
     * @param function the function to apply
     * @param <E> the evidence type
     * @param <R> the return type
     * @return the result of the function, or {@code null} if the evidence is not of the given type
     */
    default <E, R> R castAndApply(Class<E> evidenceType, String algorithmName, Function<E, R> function) {
        return evidenceType.isInstance(this) && algorithmName == null ? function.apply(evidenceType.cast(this)) : null;
    }

    /**
     * Cast this evidence type and apply a function if the type matches.
     *
     * @param evidenceType the evidence type class to check
     * @param function the function to apply
     * @param <E> the evidence type
     * @param <R> the return type
     * @return the result of the function, or {@code null} if the evidence is not of the given type
     */
    default <E, R> R castAndApply(Class<E> evidenceType, Function<E, R> function) {
        return evidenceType.isInstance(this) ? function.apply(evidenceType.cast(this)) : null;
    }
}
