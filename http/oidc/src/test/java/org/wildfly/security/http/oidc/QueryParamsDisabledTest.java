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

import static org.junit.Assume.assumeFalse;
import static org.wildfly.security.http.oidc.Oidc.ALLOW_QUERY_PARAMS_PROPERTY_NAME;

import org.apache.http.HttpStatus;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Tests for disabling query params via the {@code wildfly.elytron.oidc.allow.query.params} system property.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public class QueryParamsDisabledTest extends QueryParamsBaseTest {

    @BeforeClass
    public static void beforeClass() {
        assumeFalse("wildfly.elytron.oidc.allow.query.params should default to false",
                Boolean.parseBoolean(System.getProperty(ALLOW_QUERY_PARAMS_PROPERTY_NAME)));
    }

    /**
     * Test successfully logging in without query params included in the URL.
     */
    @Test
    public void testSuccessfulAuthenticationWithoutQueryParamsWithSystemPropertyDisabled() throws Exception {
        String originalUrl = getClientUrl();
        String expectedUrlAfterRedirect = originalUrl;
        performAuthentication(getOidcConfigurationInputStreamWithProviderUrl(), KeycloakConfiguration.ALICE,
                KeycloakConfiguration.ALICE_PASSWORD, true, HttpStatus.SC_MOVED_TEMPORARILY, originalUrl,
                expectedUrlAfterRedirect, CLIENT_PAGE_TEXT);
    }

    /**
     * Test successfully logging in with query params included in the URL.
     * The query params should not be present upon redirect.
     */
    @Test
    public void testSuccessfulAuthenticationWithQueryParamsWithSystemPropertyDisabled() throws Exception {
        String queryParams = "?myparam=abc";
        String originalUrl = getClientUrl() + queryParams;
        String expectedUrlAfterRedirect = getClientUrl();
        performAuthentication(getOidcConfigurationInputStreamWithProviderUrl(), KeycloakConfiguration.ALICE,
                KeycloakConfiguration.ALICE_PASSWORD, true, HttpStatus.SC_MOVED_TEMPORARILY,
                originalUrl, expectedUrlAfterRedirect, CLIENT_PAGE_TEXT);

        queryParams = "?one=abc&two=def&three=ghi";
        originalUrl = getClientUrl() + queryParams;
        expectedUrlAfterRedirect = getClientUrl();
        performAuthentication(getOidcConfigurationInputStreamWithProviderUrl(), KeycloakConfiguration.ALICE,
                KeycloakConfiguration.ALICE_PASSWORD, true, HttpStatus.SC_MOVED_TEMPORARILY, originalUrl,
                expectedUrlAfterRedirect, CLIENT_PAGE_TEXT);
    }

}
