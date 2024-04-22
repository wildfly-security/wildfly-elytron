/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2024 Red Hat, Inc., and individual contributors
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
package org.wildfly.security.http.oidc;

import static org.wildfly.security.http.oidc.OidcBaseTest.CLIENT_APP;

import java.io.InputStream;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Multi-tenant resolver.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public class MultiTenantResolver implements OidcClientConfigurationResolver {
    private final boolean useAuthServerUrl;

    public MultiTenantResolver(boolean useAuthServerUrl) {
        this.useAuthServerUrl = useAuthServerUrl;
    }

    private final Map<String, OidcClientConfiguration> cache = new ConcurrentHashMap<>();

    @Override
    public OidcClientConfiguration resolve(OidcHttpFacade.Request request) {
        String path = request.getURI();
        int multitenantIndex = path.indexOf(CLIENT_APP + "/");
        if (multitenantIndex == -1) {
            throw new IllegalStateException("Cannot resolve the configuration to use from the request");
        }

        String tenant = path.substring(multitenantIndex).split("/")[1];
        if (tenant.contains("?")) {
            tenant = tenant.split("\\?")[0];
        }

        OidcClientConfiguration clientConfiguration = cache.get(tenant);
        if (clientConfiguration == null) {
            // not found in the simple cache, try to load it instead
            InputStream is = useAuthServerUrl ? OidcTest.getTenantConfigWithAuthServerUrl(tenant) : OidcTest.getTenantConfigWithProviderUrl(tenant);
            if (is == null) {
                throw new IllegalStateException("Cannot find tenant configuration");
            }
            clientConfiguration = OidcClientConfigurationBuilder.build(is);
            cache.put(tenant, clientConfiguration);
        }
        return clientConfiguration;
    }

}

