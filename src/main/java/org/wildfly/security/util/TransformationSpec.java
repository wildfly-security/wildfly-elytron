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
 * Data class used by TransformationMapper instances to return desired mapping data.
 *
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>
 *
 */
public class TransformationSpec {

    public static int HIGH_STRENGTH = 300;
    public static int MEDIUM_STRENGTH = 200;
    public static int LOW_STRENGTH = 100;

    public static int NO_KEY = 0;

    private String token;
    private String transformation;
    private String provider;
    private int strength;
    private int keyLength;

    /**
     * @param token
     * @param transformation
     * @param strength
     * @param provider
     */
    public TransformationSpec(String token, String transformation, int keyLength, int strength, String provider) {
        this.token = token;
        this.transformation = transformation;
        this.strength = strength;
        this.provider = provider;
        this.keyLength = keyLength;
    }


    /**
     * @return the keyLength
     */
    public int getKeyLength() {
        return keyLength;
    }

    /**
     * @return the token
     */
    public String getToken() {
        return token;
    }

    /**
     * @return the transformation
     */
    public String getTransformation() {
        return transformation;
    }

    /**
     * @return the provider
     */
    public String getProvider() {
        return provider;
    }

    /**
     * @return the strength
     */
    public int getStrength() {
        return strength;
    }
}
