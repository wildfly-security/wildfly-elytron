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

import java.math.BigInteger;
import java.security.Key;
import java.security.interfaces.RSAMultiPrimePrivateCrtKey;
import java.security.spec.RSAOtherPrimeInfo;
import java.util.Arrays;
import java.util.Objects;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
class RawRSAMultiPrimePrivateCrtKey extends RawRSAPrivateKey implements RSAMultiPrimePrivateCrtKey {
    private static final long serialVersionUID = 6636285660549509254L;

    private final BigInteger publicExponent;
    private final BigInteger primeP;
    private final BigInteger primeQ;
    private final BigInteger primeExponentP;
    private final BigInteger primeExponentQ;
    private final BigInteger crtCoefficient;
    private final RSAOtherPrimeInfo[] otherPrimeInfo;

    RawRSAMultiPrimePrivateCrtKey(final RSAMultiPrimePrivateCrtKey original) {
        super(original);
        publicExponent = original.getPublicExponent();
        primeP = original.getPrimeP();
        primeQ = original.getPrimeQ();
        primeExponentP = original.getPrimeExponentP();
        primeExponentQ = original.getPrimeExponentQ();
        crtCoefficient = original.getCrtCoefficient();
        final RSAOtherPrimeInfo[] otherPrimeInfo = original.getOtherPrimeInfo();
        this.otherPrimeInfo = otherPrimeInfo == null ? null : otherPrimeInfo.clone();
    }

    RawRSAMultiPrimePrivateCrtKey(final Key original) {
        this((RSAMultiPrimePrivateCrtKey) original);
    }

    public BigInteger getPublicExponent() {
        return publicExponent;
    }

    public BigInteger getPrimeP() {
        return primeP;
    }

    public BigInteger getPrimeQ() {
        return primeQ;
    }

    public BigInteger getPrimeExponentP() {
        return primeExponentP;
    }

    public BigInteger getPrimeExponentQ() {
        return primeExponentQ;
    }

    public BigInteger getCrtCoefficient() {
        return crtCoefficient;
    }

    public RSAOtherPrimeInfo[] getOtherPrimeInfo() {
        final RSAOtherPrimeInfo[] otherPrimeInfo = this.otherPrimeInfo;
        return otherPrimeInfo == null ? null : otherPrimeInfo.clone();
    }

    boolean isEqual(final Key key) {
        return key instanceof RSAMultiPrimePrivateCrtKey && isEqual((RSAMultiPrimePrivateCrtKey) key);
    }

    boolean isEqual(final RSAMultiPrimePrivateCrtKey key) {
        return super.isEqual(key)
            && Objects.equals(publicExponent, key.getPublicExponent())
            && Objects.equals(primeP, key.getPrimeP())
            && Objects.equals(primeQ, key.getPrimeQ())
            && Objects.equals(primeExponentP, key.getPrimeExponentP())
            && Objects.equals(primeExponentQ, key.getPrimeExponentQ())
            && Objects.equals(crtCoefficient, key.getCrtCoefficient())
            && Arrays.deepEquals(otherPrimeInfo, key.getOtherPrimeInfo());
    }
}
