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

import static org.wildfly.security.http.oidc.OidcBaseTest.TENANT1_REALM;
import static org.wildfly.security.http.oidc.OidcBaseTest.TENANT2_REALM;
import static org.wildfly.security.http.oidc.Oidc.OIDC_SCOPE;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import javax.security.auth.x500.X500Principal;

import org.keycloak.protocol.oidc.OIDCAdvancedConfigWrapper;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.RolesRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.wildfly.security.ssl.test.util.CAGenerationTool;
import io.restassured.RestAssured;


/**
 * Keycloak configuration for testing.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public class KeycloakConfiguration {

    private static final String USER_ROLE = "user";
    private static final String ADMIN_ROLE = "admin";
    public static final String ALICE = "alice";
    public static final String ALICE_PASSWORD = "alice123+";
    private static final String BOB = "bob";
    private static final String BOB_PASSWORD = "bob123+";
    public static final String ALLOWED_ORIGIN = "http://somehost";
    public static final boolean EMAIL_VERIFIED = false;
    public static final String RSA_KEYSTORE_FILE_NAME = "jwt.keystore";
    public static final String EC_KEYSTORE_FILE_NAME = "jwtEC.keystore";
    public static final String KEYSTORE_ALIAS = "jwtKeystore";
    public static final String KEYSTORE_PASS = "Elytron";
    public static final String PKCS12_KEYSTORE_TYPE = "PKCS12";
    public static String KEYSTORE_CLASSPATH;

    /* Accepted Request Object Encrypting Algorithms for KeyCloak*/
    public static final String RSA_OAEP = "RSA-OAEP";
    public static final String RSA_OAEP_256 = "RSA-OAEP-256";
    public static final String RSA1_5 = "RSA1_5";

    /* Accepted Request Object Encryption Methods for KeyCloak*/
    public static final String A128CBC_HS256 = "A128CBC-HS256";
    public static final String A192CBC_HS384 = "A192CBC-HS384";
    public static final String A256CBC_HS512 = "A256CBC-HS512";
    public static CAGenerationTool caGenerationTool = null;
    public X509Certificate caCertificate = null;

    // the users below are for multi-tenancy tests specifically
    public static final String TENANT1_USER = "tenant1_user";
    public static final String TENANT1_PASSWORD = "tenant1_password";
    public static final String TENANT2_USER = "tenant2_user";
    public static final String TENANT2_PASSWORD = "tenant2_password";
    public static final String CHARLIE = "charlie";
    public static final String CHARLIE_PASSWORD =" charlie123+";
    public static final String DAN = "dan";
    public static final String DAN_PASSWORD =" dan123+";

    /**
     * Configure RealmRepresentation as follows:
     * <ul>
     * <li>Two realm roles ("admin", "user")</li>
     * <li>Two users:<li>
     * <ul>
     * <li>user named alice and password alice123+ with "admin" and "user" role</li>
     * <li>user named bob and password bob123+ with "user" role</li>
     * </ul>
     * </ul>
     */
    public static RealmRepresentation getRealmRepresentation(final String realmName, String clientId, String clientSecret,
                                                             String clientHostName, int clientPort, String clientApp, boolean configureClientScopes) throws Exception {
        return createRealm(realmName, clientId, clientSecret, clientHostName, clientPort, clientApp, configureClientScopes);
    }

    public static RealmRepresentation getRealmRepresentation(final String realmName, String clientId, String clientSecret,
                                                             String clientHostName, int clientPort, String clientApp, int accessTokenLifespan,
                                                             int ssoSessionMaxLifespan, boolean configureClientScopes, boolean multiTenancyApp) throws Exception {
        return createRealm(realmName, clientId, clientSecret, clientHostName, clientPort, clientApp, accessTokenLifespan, ssoSessionMaxLifespan, configureClientScopes, multiTenancyApp);
    }

    public static RealmRepresentation getRealmRepresentation(final String realmName, String clientId, String clientSecret,
                                                             String clientHostName, int clientPort, String clientApp,
                                                             boolean directAccessGrantEnabled, String bearerOnlyClientId,
                                                             String corsClientId) throws Exception {
        return createRealm(realmName, clientId, clientSecret, clientHostName, clientPort, clientApp, directAccessGrantEnabled, bearerOnlyClientId, corsClientId);
    }

    public static String getAdminAccessToken(String authServerUrl) {
        return getAdminAccessToken(authServerUrl, "master", KeycloakContainer.KEYCLOAK_ADMIN_USER,
                KeycloakContainer.KEYCLOAK_ADMIN_PASSWORD, "admin-cli");
    }

    public static String getAdminAccessToken(String authServerUrl, String realmName, String username, String password, String clientId) {
        return RestAssured
                .given()
                .param("grant_type", "password")
                .param("username", username)
                .param("password", password)
                .param("client_id", clientId)
                .when()
                .post(authServerUrl + "/realms/" + realmName + "/protocol/openid-connect/token")
                .as(AccessTokenResponse.class).getToken();
    }

    public static String getAccessToken(String authServerUrl, String realmName, String username, String password, String clientId, String clientSecret) {
        return RestAssured
                .given()
                .param("grant_type", "password")
                .param("username", username)
                .param("password", password)
                .param("client_id", clientId)
                .param("client_secret", clientSecret)
                .when()
                .post(authServerUrl + "/realms/" + realmName + "/protocol/openid-connect/token")
                .as(AccessTokenResponse.class).getToken();
    }

    private static RealmRepresentation createRealm(final String realmName, String clientId, String clientSecret,
                               String clientHostName, int clientPort, String clientApp,
                               boolean directAccessGrantEnabled, String bearerOnlyClientId,
                               String corsClientId) throws Exception {
       return createRealm(realmName, clientId, clientSecret, clientHostName, clientPort, clientApp, directAccessGrantEnabled, bearerOnlyClientId, corsClientId, false);
    }

    private static RealmRepresentation createRealm(String name, String clientId, String clientSecret,
                                                   String clientHostName, int clientPort, String clientApp, boolean configureClientScopes) throws Exception {
        return createRealm(name, clientId, clientSecret, clientHostName, clientPort, clientApp, false, null, null, configureClientScopes);
    }

    private static RealmRepresentation createRealm(String name, String clientId, String clientSecret,
                                                   String clientHostName, int clientPort, String clientApp, int accessTokenLifeSpan, int ssoSessionMaxLifespan,
                                                   boolean configureClientScopes, boolean multiTenancyApp) throws Exception {
        return createRealm(name, clientId, clientSecret, clientHostName, clientPort, clientApp, false, null, null, accessTokenLifeSpan, ssoSessionMaxLifespan, configureClientScopes, multiTenancyApp);
    }

    private static RealmRepresentation createRealm(String name, String clientId, String clientSecret,
                                                   String clientHostName, int clientPort, String clientApp,
                                                   boolean directAccessGrantEnabled, String bearerOnlyClientId,
                                                   String corsClientId, boolean configureClientScopes) throws Exception {
        return createRealm(name, clientId, clientSecret, clientHostName, clientPort, clientApp, directAccessGrantEnabled, bearerOnlyClientId, corsClientId, 3, 3, configureClientScopes, false);
    }

    private static RealmRepresentation createRealm(String name, String clientId, String clientSecret,
                                                   String clientHostName, int clientPort, String clientApp,
                                                   boolean directAccessGrantEnabled, String bearerOnlyClientId,
                                                   String corsClientId, int accessTokenLifespan, int ssoSessionMaxLifespan,
                                                   boolean configureClientScopes, boolean multiTenancyApp) throws Exception {
        RealmRepresentation realm = new RealmRepresentation();
        realm.setRealm(name);
        realm.setEnabled(true);
        realm.setUsers(new ArrayList<>());
        realm.setClients(new ArrayList<>());
        realm.setAccessTokenLifespan(accessTokenLifespan);
        realm.setSsoSessionMaxLifespan(ssoSessionMaxLifespan);

        RolesRepresentation roles = new RolesRepresentation();
        List<RoleRepresentation> realmRoles = new ArrayList<>();

        roles.setRealm(realmRoles);
        realm.setRoles(roles);

        realm.getRoles().getRealm().add(new RoleRepresentation("user", null, false));
        realm.getRoles().getRealm().add(new RoleRepresentation("admin", null, false));

        ClientRepresentation webAppClient = createWebAppClient(clientId, clientSecret, clientHostName, clientPort, clientApp, directAccessGrantEnabled, multiTenancyApp);
        if (configureClientScopes) {
            webAppClient.setDefaultClientScopes(Collections.singletonList(OIDC_SCOPE));
            webAppClient.setOptionalClientScopes(Arrays.asList("phone", "email", "profile"));
        }
        realm.getClients().add(webAppClient);

        if (bearerOnlyClientId != null) {
            realm.getClients().add(createBearerOnlyClient(bearerOnlyClientId));
        }

        if (corsClientId != null) {
            realm.getClients().add(createWebAppClient(corsClientId, clientSecret, clientHostName, clientPort, clientApp, directAccessGrantEnabled, ALLOWED_ORIGIN, multiTenancyApp));
        }

        if (name.equals(TENANT1_REALM)) {
            realm.getUsers().add(createUser(TENANT1_USER, TENANT1_PASSWORD, Arrays.asList(USER_ROLE, ADMIN_ROLE)));
            realm.getUsers().add(createUser(CHARLIE, CHARLIE_PASSWORD, Arrays.asList(USER_ROLE, ADMIN_ROLE)));
            realm.getUsers().add(createUser(DAN, DAN_PASSWORD, Arrays.asList(USER_ROLE, ADMIN_ROLE)));
        } else if (name.equals(TENANT2_REALM)) {
            realm.getUsers().add(createUser(TENANT2_USER, TENANT2_PASSWORD, Arrays.asList(USER_ROLE, ADMIN_ROLE)));
            realm.getUsers().add(createUser(CHARLIE, CHARLIE_PASSWORD, Arrays.asList(USER_ROLE, ADMIN_ROLE)));
            realm.getUsers().add(createUser(DAN, DAN_PASSWORD, Arrays.asList(USER_ROLE, ADMIN_ROLE)));
        } else {
            realm.getUsers().add(createUser(ALICE, ALICE_PASSWORD, Arrays.asList(USER_ROLE, ADMIN_ROLE)));
            realm.getUsers().add(createUser(BOB, BOB_PASSWORD, Arrays.asList(USER_ROLE)));
        }
        return realm;
    }

    private static ClientRepresentation createWebAppClient(String clientId, String clientSecret, String clientHostName, int clientPort, String clientApp,
                                                           boolean directAccessGrantEnabled, boolean multiTenancyApp) throws Exception {
        return createWebAppClient(clientId, clientSecret, clientHostName, clientPort, clientApp, directAccessGrantEnabled, null, multiTenancyApp);
    }

    private static ClientRepresentation createWebAppClient(String clientId, String clientSecret, String clientHostName, int clientPort,
                                                           String clientApp, boolean directAccessGrantEnabled, String allowedOrigin, boolean multiTenancyApp) throws Exception {
        ClientRepresentation client = new ClientRepresentation();
        client.setClientId(clientId);
        client.setPublicClient(false);
        client.setSecret(clientSecret);
        //client.setRedirectUris(Arrays.asList("*"));
        if (multiTenancyApp) {
            client.setRedirectUris(Arrays.asList("http://" + clientHostName + ":" + clientPort + "/" + clientApp + "/*"));
        } else {
            client.setRedirectUris(Arrays.asList("http://" + clientHostName + ":" + clientPort + "/" + clientApp));
        }
        client.setEnabled(true);
        client.setDirectAccessGrantsEnabled(directAccessGrantEnabled);

        if (allowedOrigin != null) {
            client.setWebOrigins(Collections.singletonList(allowedOrigin));
        }

        OIDCAdvancedConfigWrapper oidcAdvancedConfigWrapper = OIDCAdvancedConfigWrapper.fromClientRepresentation(client);
        oidcAdvancedConfigWrapper.setUseJwksUrl(false);
        KEYSTORE_CLASSPATH = Objects.requireNonNull(KeycloakConfiguration.class.getClassLoader().getResource("")).getPath();
        File ksFile = new File(KEYSTORE_CLASSPATH + RSA_KEYSTORE_FILE_NAME);
        if (ksFile.exists()) {
            InputStream stream = findFile(KEYSTORE_CLASSPATH + RSA_KEYSTORE_FILE_NAME);
            KeyStore keyStore = KeyStore.getInstance(PKCS12_KEYSTORE_TYPE);
            keyStore.load(stream, KEYSTORE_PASS.toCharArray());
            client.getAttributes().put("jwt.credential.certificate", Base64.getEncoder().encodeToString(keyStore.getCertificate(KEYSTORE_ALIAS).getEncoded()));
        } else {
            caGenerationTool = CAGenerationTool.builder()
                    .setBaseDir(KEYSTORE_CLASSPATH)
                    .setRequestIdentities(CAGenerationTool.Identity.values()) // Create all identities.
                    .build();
            X500Principal principal = new X500Principal("OU=Elytron, O=Elytron, C=UK, ST=Elytron, CN=OcspResponder");
            X509Certificate rsaCert = caGenerationTool.createIdentity(KEYSTORE_ALIAS, principal, RSA_KEYSTORE_FILE_NAME, CAGenerationTool.Identity.CA);
            client.getAttributes().put("jwt.credential.certificate", Base64.getEncoder().encodeToString(rsaCert.getEncoded()));
        }
        return client;
    }

    private static ClientRepresentation createBearerOnlyClient(String clientId) {
        ClientRepresentation client = new ClientRepresentation();
        client.setClientId(clientId);
        client.setBearerOnly(true);
        client.setEnabled(true);
        return client;
    }

    private static UserRepresentation createUser(String username, String password, List<String> realmRoles) {
        UserRepresentation user = new UserRepresentation();
        user.setUsername(username);
        user.setEnabled(true);
        user.setCredentials(new ArrayList<>());
        user.setRealmRoles(realmRoles);
        user.setEmail(username + "@gmail.com");
        user.setEmailVerified(EMAIL_VERIFIED);
        user.setFirstName("Alice");
        user.setLastName("Smith");

        CredentialRepresentation credential = new CredentialRepresentation();
        credential.setType(CredentialRepresentation.PASSWORD);
        credential.setValue(password);
        credential.setTemporary(false);
        user.getCredentials().add(credential);
        return user;
    }

    private static InputStream findFile(String keystoreFile) {
        try {
            return new FileInputStream(keystoreFile);
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        }
    }

}