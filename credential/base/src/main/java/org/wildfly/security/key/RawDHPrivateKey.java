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
import java.util.Objects;

import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.spec.DHParameterSpec;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
class RawDHPrivateKey extends RawPrivateKey implements DHPrivateKey, PrivateKey {
    private static final long serialVersionUID = - 4800398215863011448L;
    private final BigInteger x;
    private final DHParameterSpec params;

    RawDHPrivateKey(final DHPrivateKey original) {
        super(original);
        x = original.getX();
        params = original.getParams();
    }

    RawDHPrivateKey(final Key key) {
        this((DHPrivateKey) key);
    }

    public BigInteger getX() {
        return x;
    }

    public DHParameterSpec getParams() {
        return params;
    }

    boolean isEqual(final Key key) {
        return key instanceof DHPrivateKey && isEqual((DHPrivateKey) key);
    }

    boolean isEqual(final DHPrivateKey key) {
        return super.isEqual(key) && Objects.equals(x, key.getX()) && Objects.equals(params, key.getParams());
    }
}
