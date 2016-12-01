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

package org.wildfly.security.password.interfaces;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
final class RawMaskedPassword extends RawPassword implements MaskedPassword {
    private static final long serialVersionUID = - 4344349209404192377L;

    private final char[] initialKeyMaterial;
    private final int iterationCount;
    private final byte[] salt;
    private final byte[] maskedPasswordBytes;

    RawMaskedPassword(final String algorithm, final char[] initialKeyMaterial, final int iterationCount, final byte[] salt, final byte[] maskedPasswordBytes) {
        super(algorithm);
        this.initialKeyMaterial = initialKeyMaterial;
        this.iterationCount = iterationCount;
        this.salt = salt;
        this.maskedPasswordBytes = maskedPasswordBytes;
    }

    public char[] getInitialKeyMaterial() {
        return initialKeyMaterial.clone();
    }

    public int getIterationCount() {
        return iterationCount;
    }

    public byte[] getSalt() {
        return salt.clone();
    }

    public byte[] getMaskedPasswordBytes() {
        return maskedPasswordBytes.clone();
    }

    public RawMaskedPassword clone() {
        return this;
    }
}
