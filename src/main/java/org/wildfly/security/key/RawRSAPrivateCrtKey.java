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
import java.security.interfaces.RSAPrivateCrtKey;
import java.util.Objects;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
class RawRSAPrivateCrtKey extends RawRSAPrivateKey implements RSAPrivateCrtKey {
    private static final long serialVersionUID = - 4564257533496478680L;

    private final BigInteger publicExponent;
    private final BigInteger primeP;
    private final BigInteger primeQ;
    private final BigInteger primeExponentP;
    private final BigInteger primeExponentQ;
    private final BigInteger crtCoefficient;

    RawRSAPrivateCrtKey(final RSAPrivateCrtKey original) {
        super(original);
        publicExponent = original.getPublicExponent();
        primeP = original.getPrimeP();
        primeQ = original.getPrimeQ();
        primeExponentP = original.getPrimeExponentP();
        primeExponentQ = original.getPrimeExponentQ();
        crtCoefficient = original.getCrtCoefficient();
    }

    RawRSAPrivateCrtKey(final Key original) {
        this((RSAPrivateCrtKey) original);
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

    boolean isEqual(final Key key) {
        return key instanceof RSAPrivateCrtKey && isEqual((RSAPrivateCrtKey) key);
    }

    boolean isEqual(final RSAPrivateCrtKey key) {
        return super.isEqual(key)
            && Objects.equals(publicExponent, key.getPublicExponent())
            && Objects.equals(primeP, key.getPrimeP())
            && Objects.equals(primeQ, key.getPrimeQ())
            && Objects.equals(primeExponentP, key.getPrimeExponentP())
            && Objects.equals(primeExponentQ, key.getPrimeExponentQ())
            && Objects.equals(crtCoefficient, key.getCrtCoefficient());
    }
}
