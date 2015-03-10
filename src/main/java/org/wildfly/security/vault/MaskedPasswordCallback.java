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
package org.wildfly.security.vault;

/**
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>.
 */
public final class MaskedPasswordCallback extends VaultPasswordCallback {

    private final String maskedPasswordString;
    private final String salt;
    private final int iterationCount;
    private final String PBEAlgorithm;
    private final String initialKeyMaterial;

    public MaskedPasswordCallback(String maskedPasswordString, String salt, int iterationCount) {
        this(maskedPasswordString, salt, iterationCount, null, null);
    }

    public MaskedPasswordCallback(String maskedPasswordString, String salt, int iterationCount, String PBEAlgorithm, String initialKeyMaterial) {
        this.maskedPasswordString = maskedPasswordString;
        this.salt = salt;
        this.iterationCount = iterationCount;
        this.PBEAlgorithm = PBEAlgorithm;
        this.initialKeyMaterial = initialKeyMaterial;
    }

    public String getMaskedPasswordString() {
        return maskedPasswordString;
    }

    public String getSalt() {
        return salt;
    }

    public int getIterationCount() {
        return iterationCount;
    }

    public String getPBEAlgorithm() {
        return PBEAlgorithm;
    }

    public String getInitialKeyMaterial() {
        return initialKeyMaterial;
    }
}
