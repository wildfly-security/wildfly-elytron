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

import org.junit.Assert;
import org.junit.Test;
import org.keycloak.common.util.KeycloakUriBuilder;

import java.util.Collections;

/**
 * @author rmartinc
 */
public class OidcClientUriBuilderTest {

    @Test
    public void test() {
        Assert.assertEquals("http://localhost:8080/path?attr1=value1&attr2=value2",
                KeycloakUriBuilder.fromUri("http://localhost:8080/path?attr1=value1&attr2=value2")
                        .build().toString());

        Assert.assertEquals("http://localhost/path?attr1=value1&attr2=value2",
                KeycloakUriBuilder.fromUri("http://localhost:80")
                        .path("path")
                        .queryParam("attr1", "value1")
                        .queryParam("attr2", "value2")
                        .build().toString());

        Assert.assertEquals("unknown://localhost:9000/path",
                KeycloakUriBuilder.fromUri("unknown://localhost:9000/path").build().toString());

        Assert.assertEquals("https://localhost/path?attr1=value1",
                KeycloakUriBuilder.fromUri("https://{hostname}:443/path?attr1={value}")
                        .build("localhost", "value1").toString());

        Assert.assertEquals("https://localhost:8443/path?attr1=value1",
                KeycloakUriBuilder.fromUri("https://localhost:8443/path?attr1={value}")
                        .buildFromMap(Collections.singletonMap("value", "value1")).toString());
    }
}
