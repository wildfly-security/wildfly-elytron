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

package org.wildfly.security.auth;

import java.security.Provider;
import java.util.function.Supplier;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
class ProvidersAuthenticationConfiguration extends AuthenticationConfiguration {

    private final Supplier<Provider[]> providerSupplier;

    ProvidersAuthenticationConfiguration(final AuthenticationConfiguration parent, final Supplier<Provider[]> providerSupplier) {
        super(parent);
        this.providerSupplier = providerSupplier;
    }

    AuthenticationConfiguration reparent(final AuthenticationConfiguration newParent) {
        return new ProvidersAuthenticationConfiguration(newParent, providerSupplier);
    }

    Supplier<Provider[]> getProviderSupplier() {
        return providerSupplier;
    }
}
