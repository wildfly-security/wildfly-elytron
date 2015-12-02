/*
 * JBoss, Home of Professional Open Source
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
package org.wildfly.security.credential.store.external;

import org.wildfly.security.credential.Credential;

/**
 * Callback work with PBE masked passwords.
 *
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>.
 */
public final class MaskedPasswordCallback extends ExternalCredentialCallback<Credential> {

    private final String maskedPasswordString;
    private final String salt;
    private final int iterationCount;
    private final String PBEAlgorithm;
    private final String initialKeyMaterial;

    /**
     * Creates {@code MaskedPasswordCallback} based on arguments
     * @param maskedPasswordString masked password, could be prefixed with "MASK-"
     * @param salt salt PBE parameter
     * @param iterationCount iteration count PBE parameter
     */
    public MaskedPasswordCallback(String maskedPasswordString, String salt, int iterationCount) {
        this(maskedPasswordString, salt, iterationCount, null, null);
    }

    /**
     * Creates {@code MaskedPasswordCallback} based on arguments
     * @param maskedPasswordString masked password, could be prefixed with "MASK-"
     * @param salt salt PBE parameter
     * @param iterationCount iteration count PBE parameter
     * @param PBEAlgorithm PBE algorithm to use (could be {@code null} for default)
     * @param initialKeyMaterial initial key for the PBE algorithm (could be {@code null} for default)
     */
    public MaskedPasswordCallback(String maskedPasswordString, String salt, int iterationCount, String PBEAlgorithm, String initialKeyMaterial) {
        this.maskedPasswordString = maskedPasswordString;
        this.salt = salt;
        this.iterationCount = iterationCount;
        this.PBEAlgorithm = PBEAlgorithm;
        this.initialKeyMaterial = initialKeyMaterial;
    }

    /**
     * Returns the masked password {@code String}
     * @return the parameter
     */
    public String getMaskedPasswordString() {
        return maskedPasswordString;
    }

    /**
     * Returns the salt
     * @return the parameter
     */
    public String getSalt() {
        return salt;
    }

    /**
     * Returns the iteration count
     * @return the parameter
     */
    public int getIterationCount() {
        return iterationCount;
    }

    /**
     * Returns the PBE algorithm
     * @return the parameter
     */
    public String getPBEAlgorithm() {
        return PBEAlgorithm;
    }

    /**
     * Returns initial key material
     * @return the parameter
     */
    public String getInitialKeyMaterial() {
        return initialKeyMaterial;
    }
}
