/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2019 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.provider.util;

import org.junit.Test;

import java.security.Provider;
import java.util.Arrays;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import static org.junit.Assert.assertTrue;

public class ProviderFactoryTest {

    private String[] elytronProviderNames = new String[]{
            "WildFlyElytronPasswordProvider",
            "WildFlyElytronCredentialStoreProvider",
            "WildFlyElytronKeyProvider",
            "WildFlyElytronKeyStoreProvider",
            "WildFlyElytronSaslAnonymousProvider",
            "WildFlyElytronSaslDigestProvider",
            "WildFlyElytronSaslEntityProvider",
            "WildFlyElytronSaslExternalProvider",
            "WildFlyElytronSaslGs2Provider",
            "WildFlyElytronSaslGssapiProvider",
            "WildFlyElytronSaslLocalUserProvider",
            "WildFlyElytronSaslOAuth2Provider",
            "WildFlyElytronSaslOTPProvider",
            "WildFlyElytronSaslPlainProvider",
            "WildFlyElytronSaslScramProvider"
    };

    @Test
    public void findAllElytronProvidersTest() {
        Supplier<Provider[]> supplier = ProviderFactory.getDefaultProviderSupplier(ProviderFactoryTest.class.getClassLoader());
        assertTrue(Arrays.stream(supplier.get())
                .map(Provider::getName)
                .collect(Collectors.toList())
                .containsAll(Arrays.asList(this.elytronProviderNames)));
    }
}
