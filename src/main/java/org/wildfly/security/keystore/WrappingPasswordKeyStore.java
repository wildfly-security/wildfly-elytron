/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2014 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.keystore;

import java.security.KeyStore;

/**
 * A {@code KeyStore} which can store {@code TwoWayPassword} instances by wrapping another {@code KeyStore} which can store
 * {@code SecretKey} instances.  The passwords are stored by taking the clear password contents and encoding them
 * in UTF-8, and storing the resultant bytes as a {@code SecretKey}.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class WrappingPasswordKeyStore extends KeyStore {

    /**
     * Construct a new instance.
     *
     * @param delegate the delegate {@code KeyStore} (must not be {@code null})
     */
    public WrappingPasswordKeyStore(final KeyStore delegate) {
        super(new WrappingPasswordKeyStoreSpiImpl(delegate), delegate.getProvider(), delegate.getType());
    }
}
