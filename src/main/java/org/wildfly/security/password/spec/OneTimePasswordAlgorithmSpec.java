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

package org.wildfly.security.password.spec;

import java.io.Serializable;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Objects;

import org.wildfly.common.Assert;

/**
 * Algorithm parameter specification for one-time password types.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public final class OneTimePasswordAlgorithmSpec implements AlgorithmParameterSpec, Serializable  {

    private static final long serialVersionUID = 2703192508293746122L;

    private final String algorithm;
    private final String seed;
    private final int sequenceNumber;

    public OneTimePasswordAlgorithmSpec(final String algorithm, final String seed, final int sequenceNumber) {
        Assert.checkNotNullParam("algorithm", algorithm);
        Assert.checkNotNullParam("seed", seed);
        this.algorithm = algorithm;
        this.seed = seed;
        this.sequenceNumber = sequenceNumber;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public String getSeed() {
        return seed;
    }

    public int getSequenceNumber() {
        return sequenceNumber;
    }

    public boolean equals(Object other) {
        if (! (other instanceof OneTimePasswordAlgorithmSpec)) return false;
        if (this == other) return true;
        OneTimePasswordAlgorithmSpec otherSpec = (OneTimePasswordAlgorithmSpec) other;
        return sequenceNumber == otherSpec.sequenceNumber && Objects.equals(algorithm, otherSpec.algorithm) && Objects.equals(seed, otherSpec.seed);
    }

    public int hashCode() {
        return (sequenceNumber * 31 + seed.hashCode()) * 31 + algorithm.hashCode();
    }
}
