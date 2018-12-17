/*
 * JBoss, Home of Professional Open Source
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

package org.wildfly.security.util;

/**
 * TransformationMapper interface is used to map cipher tokens specified in various SASL mechanisms to transformation string used by JCE to construct new cipher algorithm.
 *
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>
 *
 */
public interface TransformationMapper {

    /**
     * Get TransformationSpec with highest strength.
     *
     * @param mechanism name as per specification. Cannot be {@code null}.
     * @param token name as per mechanism specification
     * @return TransformationSpec object
     * @throws IllegalArgumentException if there is no such mechanism or token for the mechanism
     */
    TransformationSpec getTransformationSpec(String mechanism, String token) throws IllegalArgumentException;

    /**
     * Get TransformationSpec with highest strength.
     *
     * @param provider name as defined by JCA
     * @param mechanism name as per specification. Cannot be {@code null}.
     * @param token name as per mechanism specification
     * @return TransformationSpec object
     * @throws IllegalArgumentException if there is no such mechanism or token for the mechanism
     */
    TransformationSpec getTransformationSpec(String provider, String mechanism, String token) throws IllegalArgumentException;

    /**
     * Get ordered array of TransformationSpec by strength.
     *
     * Array is ordered from the highest strength to the lowest.
     *
     * @param mechanism name as per specification. Cannot be {@code null}.
     * @param tokens - array of tokens to consider. Names as per mechanism specification.
     * @return ordered array of TransformationSpec
     * @throws IllegalArgumentException if there is no such mechanism or token for the mechanism
     */
    TransformationSpec[] getTransformationSpecByStrength(String mechanism, String... tokens) throws IllegalArgumentException;

    /**
     * Get ordered array of TransformationSpec by strength.
     *
     * Array is ordered from the highest strength to the lowest.
     *
     * @param provider name as defined by JCA
     * @param mechanism name as per specification. Cannot be {@code null}.
     * @param tokens - array of tokens to consider. Names as per mechanism specification.
     * @return ordered array of TransformationSpec
     * @throws IllegalArgumentException if there is no such mechanism or token for the mechanism
     */
    TransformationSpec[] getTransformationSpecByStrength(String provider, String mechanism, String... tokens) throws IllegalArgumentException;

    /**
     * Get array of TransformationSpec with given strength.
     *
     * @param mechanism name as per specification. Cannot be {@code null}.
     * @param strength of desired transformation
     * @param tokens - array of tokens to consider. Names as per mechanism specification.
     * @return array of TransformationSpec
     * @throws IllegalArgumentException if there is no such mechanism or token for the mechanism
     */
    TransformationSpec[] getTransformationSpecWithStrength(String mechanism, int strength, String... tokens) throws IllegalArgumentException;


    /**
     * Get array of TransformationSpec with given strength.
     *
     * @param provider name as defined by JCA
     * @param mechanism name as per specification. Cannot be {@code null}.
     * @param strength of desired transformation
     * @param tokens - array of tokens to consider. Names as per mechanism specification.
     * @return array of TransformationSpec
     * @throws IllegalArgumentException if there is no such mechanism or token for the mechanism
     */
    TransformationSpec[] getTransformationSpecWithStrength(String provider, String mechanism, int strength, String... tokens) throws IllegalArgumentException;

}
