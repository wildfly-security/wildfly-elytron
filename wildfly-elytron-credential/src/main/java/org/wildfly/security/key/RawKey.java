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

package org.wildfly.security.key;

import java.io.Serializable;
import java.security.Key;
import java.util.Arrays;
import java.util.Objects;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
abstract class RawKey implements Serializable {

    private static final long serialVersionUID = -5953606815393608941L;

    private final String algorithm;
    private final String format;
    private final byte[] encoded;

    RawKey(Key original) {
        algorithm = original.getAlgorithm();
        format = original.getFormat();
        final byte[] encoded = original.getEncoded();
        this.encoded = encoded == null ? null : encoded.clone();
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public String getFormat() {
        return format;
    }

    public byte[] getEncoded() {
        final byte[] encoded = this.encoded;
        return encoded == null ? null : encoded.clone();
    }

    public final boolean equals(final Object obj) {
        return this == obj || obj instanceof Key && isEqual((Key) obj);
    }

    @Override
    public int hashCode() {
        return (algorithm != null ? algorithm.hashCode() : 1) +
                (format != null ? format.hashCode() : 3) +
                Arrays.hashCode(encoded);
    }

    boolean isEqual(Key key) {
        return Objects.equals(key.getAlgorithm(), algorithm) && Objects.equals(key.getFormat(), format);
    }
}
