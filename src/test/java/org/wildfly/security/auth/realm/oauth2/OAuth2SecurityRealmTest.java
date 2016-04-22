/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.auth.realm.oauth2;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.Principal;
import java.util.Arrays;
import java.util.function.Function;

import javax.json.Json;
import javax.json.JsonArrayBuilder;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.authz.Attributes;
import org.wildfly.security.authz.AuthorizationIdentity;
import org.wildfly.security.evidence.BearerTokenEvidence;

import mockit.Mock;
import mockit.MockUp;
import mockit.integration.junit4.JMockit;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
@RunWith(JMockit.class)
public class OAuth2SecurityRealmTest {

    @Test
    public void testBasicActiveToken() throws Exception {
        configureReplayTokenIntrospection();

        OAuth2SecurityRealm securityRealm = OAuth2SecurityRealm.builder()
                .clientId("wildfly-elytron")
                .clientSecret("dont_tell_me")
                .tokenIntrospectionUrl(new URL("http://as.test.org/oauth2/token/introspect"))
                .build();

        JsonObjectBuilder tokenBuilder = Json.createObjectBuilder();

        tokenBuilder.add("active", true);
        tokenBuilder.add("username", "elytron@jboss.org");

        RealmIdentity realmIdentity = securityRealm.getRealmIdentity(null, null, new BearerTokenEvidence(tokenBuilder.build().toString()));

        assertTrue(realmIdentity.exists());

        Principal realmIdentityPrincipal = realmIdentity.getRealmIdentityPrincipal();

        assertEquals("elytron@jboss.org", realmIdentityPrincipal.getName());
    }

    @Test
    public void testNotActiveToken() throws Exception {
        configureReplayTokenIntrospection();

        OAuth2SecurityRealm securityRealm = OAuth2SecurityRealm.builder()
                .clientId("wildfly-elytron")
                .clientSecret("dont_tell_me")
                .tokenIntrospectionUrl(new URL("http://as.test.org/oauth2/token/introspect"))
                .build();

        JsonObjectBuilder tokenBuilder = Json.createObjectBuilder();

        tokenBuilder.add("active", false);

        RealmIdentity realmIdentity = securityRealm.getRealmIdentity(null, null, new BearerTokenEvidence(tokenBuilder.build().toString()));

        assertFalse(realmIdentity.exists());
        assertNull(realmIdentity.getRealmIdentityPrincipal());
    }

    @Test
    public void testAttributesFromTokenMetadata() throws Exception {
        configureReplayTokenIntrospection();

        OAuth2SecurityRealm securityRealm = OAuth2SecurityRealm.builder()
                .clientId("wildfly-elytron")
                .clientSecret("dont_tell_me")
                .tokenIntrospectionUrl(new URL("http://as.test.org/oauth2/token/introspect"))
                .build();

        JsonObjectBuilder tokenBuilder = Json.createObjectBuilder();

        tokenBuilder.add("active", true);
        tokenBuilder.add("username", "elytron@jboss.org");
        tokenBuilder.add("attribute1", "value1");
        tokenBuilder.add("attribute2", "value2");
        tokenBuilder.add("attribute3", true);
        tokenBuilder.add("attribute4", false);
        tokenBuilder.add("attribute5", 10);

        JsonArrayBuilder jsonArray = Json.createArrayBuilder();

        jsonArray.add(1).add(2).add(3).add(4);

        tokenBuilder.add("attribute6", jsonArray.build());
        tokenBuilder.add("attribute7", Json.createObjectBuilder().add("objField1", "value1").add("objectField2", "value2"));

        RealmIdentity realmIdentity = securityRealm.getRealmIdentity(null, null, new BearerTokenEvidence(tokenBuilder.build().toString()));
        AuthorizationIdentity authorizationIdentity = realmIdentity.getAuthorizationIdentity();
        Attributes attributes = authorizationIdentity.getAttributes();

        assertEquals("value1", attributes.getFirst("attribute1"));
        assertEquals("value2", attributes.getFirst("attribute2"));
        assertEquals("true", attributes.getFirst("attribute3"));
        assertEquals("false", attributes.getFirst("attribute4"));
        assertEquals("10", attributes.getFirst("attribute5"));

        Attributes.Entry attribute6 = attributes.get("attribute6");

        assertEquals(4, attribute6.size());
        assertTrue(attribute6.containsAll(Arrays.asList("1","2","3","4")));

        assertEquals("{\"objField1\":\"value1\",\"objectField2\":\"value2\"}", attributes.getFirst("attribute7"));
    }

    @Test(expected = RealmUnavailableException.class)
    public void testInErrorTokenIntrospectionEndpoint() throws Exception {
        configureTokenIntrospectionEndpoint(s ->  {throw new RuntimeException("Forcing exception.");});

        OAuth2SecurityRealm securityRealm = OAuth2SecurityRealm.builder()
                .clientId("wildfly-elytron")
                .clientSecret("dont_tell_me")
                .tokenIntrospectionUrl(new URL("http://as.test.org/oauth2/token/introspect"))
                .build();

        JsonObjectBuilder tokenBuilder = Json.createObjectBuilder();

        tokenBuilder.add("active", true);

        RealmIdentity realmIdentity = securityRealm.getRealmIdentity(null, null, new BearerTokenEvidence(tokenBuilder.build().toString()));

        assertFalse(realmIdentity.exists());
    }

    @Test(expected = IllegalStateException.class)
    public void failMissingSSLContext() throws Exception {
        OAuth2SecurityRealm securityRealm = OAuth2SecurityRealm.builder()
                .clientId("wildfly-elytron")
                .clientSecret("dont_tell_me")
                .tokenIntrospectionUrl(new URL("https://as.test.org/oauth2/token/introspect"))
                .build();
    }

    @Test(expected = IllegalStateException.class)
    public void failMissingHostnameverifier() throws Exception {
        OAuth2SecurityRealm securityRealm = OAuth2SecurityRealm.builder()
                .clientId("wildfly-elytron")
                .clientSecret("dont_tell_me")
                .tokenIntrospectionUrl(new URL("https://as.test.org/oauth2/token/introspect"))
                .useSslContext(SSLContext.getDefault())
                .build();
    }

    private void configureReplayTokenIntrospection() {
        configureTokenIntrospectionEndpoint(s -> Json.createReader(new ByteArrayInputStream(s.getBytes(StandardCharsets.UTF_8))).readObject());
    }

    private void configureTokenIntrospectionEndpoint(Function<String, JsonObject> introspector){
        final Class<?> classToMock;
        try {
            classToMock = Class.forName("org.wildfly.security.auth.realm.oauth2.OAuth2Util", true, OAuth2SecurityRealm.class.getClassLoader());
        } catch (ClassNotFoundException e) {
            throw new NoClassDefFoundError(e.getMessage());
        }
        new MockUp<Object>(classToMock){
            @Mock
            public JsonObject introspectAccessToken(URL tokenIntrospectionUrl, String clientId, String clientSecret, String token, SSLContext sslContext, HostnameVerifier hostnameVerifier) throws IOException {
                return introspector.apply(token);
            }
        };
    }
}
