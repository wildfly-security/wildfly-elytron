/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2024 Red Hat, Inc., and individual contributors
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

import static org.junit.Assume.assumeTrue;

import org.junit.AfterClass;
import org.junit.BeforeClass;

import io.restassured.RestAssured;
import okhttp3.mockwebserver.MockWebServer;

/**
 * Tests for the {@code wildfly.elytron.oidc.allow.query.params} system property.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public class QueryParamsBaseTest extends OidcBaseTest {

    @BeforeClass
    public static void startTestContainers() throws Exception {
        assumeTrue("Docker isn't available, OIDC tests will be skipped", isDockerAvailable());
        KEYCLOAK_CONTAINER = new KeycloakContainer();
        KEYCLOAK_CONTAINER.start();
        sendRealmCreationRequest(KeycloakConfiguration.getRealmRepresentation(TEST_REALM, CLIENT_ID, CLIENT_SECRET, CLIENT_HOST_NAME, CLIENT_PORT, CLIENT_APP, 3, 3, false, true));
        client = new MockWebServer();
        client.start(CLIENT_PORT);
    }

    @AfterClass
    public static void generalCleanup() throws Exception {
        if (KEYCLOAK_CONTAINER != null) {
            RestAssured
                    .given()
                    .auth().oauth2(KeycloakConfiguration.getAdminAccessToken(KEYCLOAK_CONTAINER.getAuthServerUrl()))
                    .when()
                    .delete(KEYCLOAK_CONTAINER.getAuthServerUrl() + "/admin/realms/" + TEST_REALM).then().statusCode(204);
            KEYCLOAK_CONTAINER.stop();
        }
        if (client != null) {
            client.shutdown();
        }
    }

}
