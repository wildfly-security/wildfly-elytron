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
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.Objects;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
class RawRSAPrivateKey extends RawKey implements RSAPrivateKey, PrivateKey {
    private static final long serialVersionUID = - 184627557213615873L;

    private final BigInteger privateExponent;
    private final BigInteger modulus;

    RawRSAPrivateKey(final RSAPrivateKey original) {
        super(original);
        privateExponent = original.getPrivateExponent();
        modulus = original.getModulus();
    }

    RawRSAPrivateKey(final Key original) {
        this((RSAPrivateKey) original);
    }

    public BigInteger getPrivateExponent() {
        return privateExponent;
    }

    public BigInteger getModulus() {
        return modulus;
    }

    boolean isEqual(final Key key) {
        return key instanceof RSAPrivateKey && isEqual((RSAPrivateKey) key);
    }

    boolean isEqual(final RSAPrivateKey key) {
        return super.isEqual(key) && Objects.equals(privateExponent, key.getPrivateExponent()) && Objects.equals(modulus, key.getModulus());
    }
}
