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
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECParameterSpec;
import java.util.Objects;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
class RawECPrivateKey extends RawPrivateKey implements ECPrivateKey, PrivateKey {
    private static final long serialVersionUID = - 7911268659221164137L;
    private final BigInteger s;
    private final ECParameterSpec params;

    RawECPrivateKey(final ECPrivateKey original) {
        super(original);
        s = original.getS();
        params = original.getParams();
    }

    RawECPrivateKey(final Key original) {
        this((ECPrivateKey) original);
    }

    public BigInteger getS() {
        return s;
    }

    public ECParameterSpec getParams() {
        return params;
    }

    boolean isEqual(final Key key) {
        return key instanceof ECPrivateKey && isEqual((ECPrivateKey) key);
    }

    boolean isEqual(final ECPrivateKey key) {
        return super.isEqual(key) && Objects.equals(s, key.getS()) && Objects.equals(params, key.getParams());
    }
}
