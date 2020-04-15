/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2020 Red Hat, Inc., and individual contributors
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
package org.wildfly.security.tool;

import java.security.Provider;
import java.util.Collections;
import org.wildfly.security.credential.store.CredentialStore;

public class CustomPropertiesProvider extends Provider {

    public static final String CUSTOM_PROPERTIES_PROVIDER = CustomPropertiesProvider.class.getSimpleName();

    public CustomPropertiesProvider() {
        super(CUSTOM_PROPERTIES_PROVIDER, 1.0, CUSTOM_PROPERTIES_PROVIDER);
        putService(new Provider.Service(this, CredentialStore.CREDENTIAL_STORE_TYPE, CustomPropertiesCredentialStore.CUSTOM_PROPERTIES_CREDENTIAL_STORE,
                CustomPropertiesCredentialStore.class.getName(), Collections.emptyList(), Collections.emptyMap()));
    }
}
