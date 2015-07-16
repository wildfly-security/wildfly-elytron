/*
 * JBoss, Home of Professional Open Source.
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

package org.wildfly.security.auth.callback;

import org.wildfly.common.Assert;

import java.io.Serializable;

/**
 * A callback to inform the callback handler of the public key type to be used.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public final class KeyTypeCallback implements ExtendedCallback, Serializable {

    private static final long serialVersionUID = -7933564870333896205L;

    /**
     * @serial The key algorithm type name.
     */
    private final String keyType;

    /**
     * Construct a new instance.
     *
     * @param keyType the key algorithm type name
     */
    public KeyTypeCallback(final String keyType) {
        Assert.checkNotNullParam("keyType", keyType);
        this.keyType = keyType;
    }

    /**
     * Get the key type.
     *
     * @return the key type
     */
    public String getKeyType() {
        return keyType;
    }
}
