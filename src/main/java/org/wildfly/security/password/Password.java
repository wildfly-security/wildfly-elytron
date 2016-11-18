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

package org.wildfly.security.password;

import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;
import java.util.function.Function;

/**
 * A password key.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public interface Password extends Key, Cloneable {

    /**
     * Cast this password type if the type and algorithm matches.
     *
     * @param passwordType the password type class to check
     * @param algorithmName the name of the algorithm or {@code null} if any algorithm is acceptable
     * @param <P> the password type
     * @return the password cast as the target type, or {@code null} if the password does not match the criteria
     */
    default <P extends Password> P castAs(Class<P> passwordType, String algorithmName) {
        return castAndApply(passwordType, algorithmName, Function.identity());
    }

    /**
     * Cast this password type if the type matches.
     *
     * @param passwordType the password type class to check
     * @param <P> the password type
     * @return the password cast as the target type, or {@code null} if the password does not match the criteria
     */
    default <P extends Password> P castAs(Class<P> passwordType) {
        return castAndApply(passwordType, Function.identity());
    }

    /**
     * Cast this password type and apply a function if the type matches.
     *
     * @param passwordType the password type class to check
     * @param algorithmName the name of the algorithm or {@code null} if any algorithm is acceptable
     * @param function the function to apply
     * @param <P> the password type
     * @param <R> the return type
     * @return the result of the function, or {@code null} if the password is not of the given type
     */
    default <P extends Password, R> R castAndApply(Class<P> passwordType, String algorithmName, Function<P, R> function) {
        return passwordType.isInstance(this) && (algorithmName == null || algorithmName.equals(getAlgorithm())) ? function.apply(passwordType.cast(this)) : null;
    }

    /**
     * Cast this password type and apply a function if the type matches.
     *
     * @param passwordType the password type class to check
     * @param function the function to apply
     * @param <P> the password type
     * @param <R> the return type
     * @return the result of the function, or {@code null} if the password is not of the given type
     */
    default <P extends Password, R> R castAndApply(Class<P> passwordType, Function<P, R> function) {
        return passwordType.isInstance(this) ? function.apply(passwordType.cast(this)) : null;
    }

    /**
     * Get the applicable algorithm parameter specification for this password type.
     *
     * @return the algorithm parameter specification, or {@code null} if this password type does not support algorithms
     */
    default AlgorithmParameterSpec getParameterSpec() {
        return null;
    }

    /**
     * Creates and returns a copy of this {@link Password}.
     *
     * @return a copy of this {@link Password}.
     */
    Password clone();

}
