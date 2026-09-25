/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.http.oidc;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.net.URL;
import java.util.Collections;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.apache.http.client.HttpClient;
import org.apache.http.impl.client.HttpClients;
import org.junit.After;
import org.junit.Before;
import org.wildfly.security.jose.jwks.JwksException;
import org.junit.Test;

/**
 * Unit tests for {@link ApacheHttpJwksFetcher}.
 *
 * @author <a href="mailto:rojeda@redhat.com">Raul Ojeda Robles</a>
 */
public class ApacheHttpJwksFetcherTest {

    private MockWebServer server;
    private HttpClient httpClient;

    @Before
    public void setUp() throws IOException {
        server = new MockWebServer();
        server.start();
        httpClient = HttpClients.createDefault();
    }

    @After
    public void tearDown() throws IOException {
        server.shutdown();
    }

    private URL serverUrl(String path) {
        return server.url(path).url();
    }

    @Test
    public void testSuccessfulResponseReturnsBody() throws Exception {
        byte[] body = "hello world".getBytes();
        server.enqueue(new MockResponse().setBody(new String(body)));
        ApacheHttpJwksFetcher fetcher = new ApacheHttpJwksFetcher(httpClient);

        byte[] result = fetcher.fetch(serverUrl("/"));
        assertArrayEquals(body, result);
    }

    @Test
    public void testNon200StatusThrowsJwksException() throws Exception {
        server.enqueue(new MockResponse().setResponseCode(404));
        ApacheHttpJwksFetcher fetcher = new ApacheHttpJwksFetcher(httpClient);

        JwksException e = assertThrows(JwksException.class, () -> fetcher.fetch(serverUrl("/")));
        assertTrue("expected the status code in the message: " + e.getMessage(), e.getMessage().contains("404"));
    }

    @Test
    public void testResponseAtCapSucceeds() throws Exception {
        byte[] body = new byte[100];
        server.enqueue(new MockResponse().setBody(new String(body)));
        ApacheHttpJwksFetcher fetcher = new ApacheHttpJwksFetcher(httpClient, Collections.emptyMap(), 100);

        byte[] result = fetcher.fetch(serverUrl("/"));
        assertNotNull(result);
    }

    @Test
    public void testResponseExceedingCapThrowsJwksException() throws Exception {
        byte[] body = new byte[101];
        server.enqueue(new MockResponse().setBody(new String(body)));
        ApacheHttpJwksFetcher fetcher = new ApacheHttpJwksFetcher(httpClient, Collections.emptyMap(), 100);

        JwksException e = assertThrows(JwksException.class, () -> fetcher.fetch(serverUrl("/")));
        assertTrue("expected a size-related message: " + e.getMessage(), e.getMessage().contains("100"));
    }
}
