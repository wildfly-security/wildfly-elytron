/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2021 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.wildfly.security.http.oidc;

import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;

/**
 * KeycloakContainer for testing.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public class KeycloakContainer extends GenericContainer<KeycloakContainer> {
    public static final String KEYCLOAK_ADMIN_USER = "admin";
    public static final String KEYCLOAK_ADMIN_PASSWORD = "admin";

    private static final String KEYCLOAK_IMAGE = "quay.io/keycloak/keycloak:24.0.1";

    private static final int KEYCLOAK_PORT_HTTP = 8080;
    private static final int KEYCLOAK_PORT_HTTPS = 8443;
    private String relativeUrl;

    private boolean useHttps;

    public KeycloakContainer() {
        this(false);
    }

    public KeycloakContainer(String relativeUrl) {
        super(KEYCLOAK_IMAGE);
        this.useHttps = false;
        this.relativeUrl = relativeUrl;
    }

    public KeycloakContainer(final boolean useHttps) {
        super(KEYCLOAK_IMAGE);
        this.useHttps = useHttps;

    }

    @Override
    protected void configure() {
        if (relativeUrl != null) {
            withEnv("KC_HTTP_RELATIVE_PATH", relativeUrl);
        }
        waitingFor(Wait.forLogMessage(".*Running the server in development mode. DO NOT use this configuration in production.*", 1));
        withExposedPorts(KEYCLOAK_PORT_HTTP, KEYCLOAK_PORT_HTTPS);
        withEnv("KEYCLOAK_ADMIN", KEYCLOAK_ADMIN_USER);
        withEnv("KEYCLOAK_ADMIN_PASSWORD", KEYCLOAK_ADMIN_PASSWORD);
        withCommand("start-dev");
    }

    public String getAuthServerUrl() {
        String host = getHost();
        int port = getMappedPort(useHttps ? KEYCLOAK_PORT_HTTPS : KEYCLOAK_PORT_HTTP);
        String url;
        if (relativeUrl != null) {
            url = String.format("http://%s:%s/%s", host, port, relativeUrl);
        } else {
            url = String.format("http://%s:%s", host, port);
        }
        return url;
    }
}
