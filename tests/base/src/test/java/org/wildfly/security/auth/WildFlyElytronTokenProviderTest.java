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
package org.wildfly.security.auth;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;
import static org.wildfly.common.Assert.assertTrue;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.concurrent.TimeUnit;
import javax.security.auth.x500.X500Principal;
import org.eclipse.microprofile.jwt.JsonWebToken;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.wildfly.security.auth.permission.LoginPermission;
import org.wildfly.security.auth.principal.NamePrincipal;
import org.wildfly.security.auth.realm.FileSystemSecurityRealm;
import org.wildfly.security.auth.server.ModifiableRealmIdentity;
import org.wildfly.security.auth.server.ModifiableSecurityRealm;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.auth.server.SecurityIdentity;
import org.wildfly.security.auth.server.ServerAuthenticationContext;
import org.wildfly.security.auth.server.jwt.TokenUtil;
import org.wildfly.security.authz.MapAttributes;
import org.wildfly.security.auth.server.jwt.WildFlyElytronTokenProvider;
import org.wildfly.security.credential.BearerTokenCredential;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.evidence.PasswordGuessEvidence;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.WildFlyElytronPasswordProvider;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.sasl.plain.WildFlyElytronSaslPlainProvider;
import org.wildfly.security.x500.cert.SelfSignedX509CertificateAndSigningKey;
import io.smallrye.jwt.algorithm.KeyEncryptionAlgorithm;
import io.smallrye.jwt.algorithm.SignatureAlgorithm;


/**
 * Tests to verify dynamic token issuance and verification
 * using the {@link WildFlyElytronTokenProvider}
 *
 * @author <a href="mailto:szaldana@redhat.com">Sonia Zaldana</a>
 */
public class WildFlyElytronTokenProviderTest {

    private final String USER = "Sonia";
    private final String PASSWORD = "secretPassword";
    private final String REALM_NAME = "default";
    private final String ISSUER = "WildFly Elytron";
    private final String AUDIENCE = "JWT";
    private static final String PLAIN = "PLAIN";


    private static final Provider[] providers = new Provider[] {
            WildFlyElytronSaslPlainProvider.getInstance(),
            WildFlyElytronPasswordProvider.getInstance()
    };

    @BeforeClass
    public static void onBefore()  {
        Security.addProvider(providers[0]);
        Security.addProvider(providers[1]);
    }

    @AfterClass
    public static void onAfter() {
        Security.removeProvider(providers[0].getName());
        Security.removeProvider(providers[1].getName());
    }

    /**
     *  Tests using a security identity and default token configuration
     *  to issue JWT tokens. Then, verifies the token and its contents.
     */
    @Test
    public void testIssuingTokenWithDefaultTokenProvider() throws Exception {
        // Default token configuration
        WildFlyElytronTokenProvider tokenProvider = WildFlyElytronTokenProvider.builder()
                .build();

        SecurityIdentity identity = fetchSecurityIdentity(tokenProvider);
        String accessToken = tokenProvider.issueAccessToken(identity);
        assertNotNull(accessToken);

        // Validate the contents of the access token is what we configured
        JsonWebToken accessJwt = tokenProvider.parseAndVerifyAccessToken(accessToken);
        assertNotNull(accessJwt);
        assertEquals(accessJwt.getIssuer(), ISSUER);
        assertEquals(accessJwt.getSubject(), USER);
        assertEquals(accessJwt.getAudience(), new HashSet<>(Arrays.asList(AUDIENCE)));
        assertEquals(accessJwt.getGroups(), new HashSet<>(Arrays.asList("Employee", "Admin", "Manager")));

        deleteKeyStore(tokenProvider.getKeyStorePath());
    }


    /**
     * Test issuing a token and adding it as a private credential to the security identity
     */
    @Test
    public void testAddingTokenAsPrivateCredential() throws Exception {
        // Default token configuration
        WildFlyElytronTokenProvider tokenProvider = WildFlyElytronTokenProvider.builder()
                .build();

        SecurityIdentity identity = fetchSecurityIdentity(tokenProvider);
        String accessToken = tokenProvider.issueAccessToken(identity);
        assertNotNull(accessToken);

        // Test using constructor to add it as private credential to security identity
        SecurityIdentity identityWithToken = identity.withPrivateCredential(new BearerTokenCredential(accessToken));
        BearerTokenCredential tokenCredential = identityWithToken.getPrivateCredentials().getCredential(BearerTokenCredential.class);
        assertNotNull(tokenCredential);
        assertNotNull(tokenCredential.getToken());

        deleteKeyStore(tokenProvider.getKeyStorePath());
    }

    /**
     * The default token provider only signs by default, but they can be encrypted by specifying an encryption alias.
     * @throws Exception
     */
    @Test
    public void testIssuingTokenWithSigningAndEncryption() throws Exception {

        WildFlyElytronTokenProvider tokenProvider = WildFlyElytronTokenProvider.builder()
                .setEncryptionAlias("myEncryptionAlias")
                .build();

        SecurityIdentity identity = fetchSecurityIdentity(tokenProvider);
        String accessToken = tokenProvider.issueAccessToken(identity);
        assertNotNull(accessToken);

        // Validate the contents of the access token is what we configured
        JsonWebToken accessJwt = tokenProvider.parseAndVerifyAccessToken(accessToken);
        assertNotNull(accessJwt);
        assertEquals(accessJwt.getIssuer(), ISSUER);
        assertEquals(accessJwt.getSubject(), USER);
        assertEquals(accessJwt.getAudience(), new HashSet<>(Arrays.asList(AUDIENCE)));
        assertEquals(accessJwt.getGroups(), new HashSet<>(Arrays.asList("Employee", "Admin", "Manager")));

        deleteKeyStore(tokenProvider.getKeyStorePath());
    }


    /**
     * Test issuing and verifying token using symmetric encryption
     */
    @Test
    public void testIssuingTokenUsingSymmetricEncryption() throws Exception {

        // Token configuration using symmetric encryption
        WildFlyElytronTokenProvider tokenProvider = WildFlyElytronTokenProvider.builder()
                .setSecret("hsAjskfRrfndsAshfnsaDFDjhfdsbnmx")
                .build();


        // Fetch security identity to test issuing the token
        SecurityIdentity identity = fetchSecurityIdentity(tokenProvider);
        String jwtToken = tokenProvider.issueAccessToken(identity);
        assertNotNull(jwtToken);

        // Validate the contents of the JWT is what we configured
        JsonWebToken jwt = tokenProvider.parseAndVerifyAccessToken(jwtToken);
        assertNotNull(jwt);
        assertEquals(jwt.getIssuer(), ISSUER);
        assertEquals(jwt.getSubject(), USER);
        assertEquals(jwt.getAudience(), new HashSet<>(Arrays.asList(AUDIENCE)));
        assertEquals(jwt.getGroups(), new HashSet<>(Arrays.asList("Employee", "Admin", "Manager")));

        deleteKeyStore(tokenProvider.getKeyStorePath());
    }


    /**
     *  Tests using a security identity and a custom token configuration
     *  to issue JWT tokens.
     *
     *  In this example, we assume user already has configured
     *  a keystore they want to use, so we specify where this keystore is located along
     *  with the required aliases and password.
     */
    @Test
    public void testIssuingTokenWithCustomConfig() throws Exception {
        generateUserKeyStore("myKeystore.jks", "mySigningAlias", "myEncryptionAlias", "mySecret");

        // Custom token configuration
        WildFlyElytronTokenProvider tokenProvider = WildFlyElytronTokenProvider.builder()
                .setEncryptionAlias("myEncryptionAlias")
                .setSigningAlias("mySigningAlias")
                .setKeyStorePassword("mySecret")
                .setKeyStorePath(Paths.get("myKeystore.jks"))
                .setAccessTokenExpiryTime(400)
                .setRefreshTokenExpiryTime(12300000)
                .setIssuer("Some Issuer")
                .setAudience(new HashSet<>(Arrays.asList("JWT1", "JWT2")))
                .setSignatureAlgorithm(SignatureAlgorithm.RS512)
                .setKeyEncryptionAlgorithm(KeyEncryptionAlgorithm.RSA_OAEP)
                .setKeySize(4096)
                .build();

        // Fetch security identity to test issuing the token
        SecurityIdentity identity = fetchSecurityIdentity(tokenProvider);
        String jwtToken = tokenProvider.issueAccessToken(identity);
        assertNotNull(jwtToken);

        // Validate the contents of the JWT is what we configured
        JsonWebToken jwt = tokenProvider.parseAndVerifyAccessToken(jwtToken);
        assertNotNull(jwt);
        assertEquals(jwt.getIssuer(), "Some Issuer");
        assertEquals(jwt.getSubject(), "Sonia");
        assertEquals(jwt.getAudience(), new HashSet<>(Arrays.asList("JWT1", "JWT2")));
        assertEquals(jwt.getGroups(), new HashSet<>(Arrays.asList("Employee", "Admin", "Manager")));

        deleteKeyStore(tokenProvider.getKeyStorePath());
    }

    /**
     * Test verifies issuing and parsing tokens that have only been signed.
     */
    @Test
    public void testIssuingOnlySignedToken() throws Exception {
        generateUserKeyStore("myKeystore.jks", "mySigningAlias", "mySecret");

        WildFlyElytronTokenProvider tokenProvider = WildFlyElytronTokenProvider.builder()
                .setSigningAlias("mySigningAlias")
                .setKeyStorePassword("mySecret")
                .setKeyStorePath(Paths.get("myKeystore.jks"))
                .build();

        // Fetch security identity to test issuing the token
        SecurityIdentity identity = fetchSecurityIdentity(tokenProvider);
        String jwtToken = tokenProvider.issueAccessToken(identity);
        assertNotNull(jwtToken);

        // Validate the contents of the JWT is what we configured
        JsonWebToken jwt = tokenProvider.parseAndVerifyAccessToken(jwtToken);
        assertNotNull(jwt);
        assertEquals(jwt.getIssuer(), ISSUER);
        assertEquals(jwt.getSubject(), USER);
        assertEquals(jwt.getAudience(), new HashSet<>(Arrays.asList(AUDIENCE)));
        assertEquals(jwt.getGroups(), new HashSet<>(Arrays.asList("Employee", "Admin", "Manager")));

        deleteKeyStore(tokenProvider.getKeyStorePath());
    }

    /**
     * Test verifies we get exceptions when using a user provided keystore and not providing the necessary parameters
     */
    @Test
    public void testMissingParametersWithUserProvidedKeystore() throws Exception {
        generateUserKeyStore("myKeystore.jks", "mySigningAlias", "myEncryptionAlias", "mySecret");

        try {
            WildFlyElytronTokenProvider missingKeystorePassword = WildFlyElytronTokenProvider.builder()
                    .setSigningAlias("mySigningAlias")
                    .setEncryptionAlias("myEncryptionAlias")
                    .setKeyStorePath(Paths.get("myKeystore.jks"))
                    .build();
            fail("IllegalStateException should come up when specifying user provided keystore without a password");
        } catch (Exception e) {
        }

        try {
            WildFlyElytronTokenProvider onlyEncryption = WildFlyElytronTokenProvider.builder()
                    .setEncryptionAlias("myEncryptionAlias")
                    .setKeyStorePassword("mySecret")
                    .setKeyStorePath(Paths.get("myKeystore.jks"))
                    .build();
            fail("IllegalStateException should come up when specifying user provided keystore with an encryption alias and no signing alias");
        } catch (Exception e) {
        }

        try {
            WildFlyElytronTokenProvider missingAliases = WildFlyElytronTokenProvider.builder()
                    .setKeyStorePassword("mySecret")
                    .setKeyStorePath(Paths.get("myKeystore.jks"))
                    .build();
            fail("IllegalStateException should come up when specifying user provided keystore with missing encryption and signing aliases");
        } catch (Exception e) {
        }

        deleteKeyStore(Paths.get("myKeystore.jks"));

    }


    /**
     * Test verifies utility methods to generate access and refresh tokens,
     * as well as methods to fetch the tokens from the security identity.
     */
    @Test
    public void testFetchingAndUpdatingTokenCredentials() throws Exception {
        WildFlyElytronTokenProvider tokenProvider = WildFlyElytronTokenProvider.builder()
                .build();

        SecurityIdentity identity = fetchSecurityIdentity(tokenProvider);

        // Check whether identity has access token
        String accessToken = TokenUtil.getAccessToken(identity);
        Assert.assertNull(accessToken);

        // Add access and refresh token. Verify they were both added.
        SecurityIdentity identityWithCredentials = TokenUtil.updateTokenCredentials(identity, tokenProvider);
        accessToken = TokenUtil.getAccessToken(identityWithCredentials);
        Assert.assertNotNull(accessToken);
        String refreshToken = TokenUtil.getRefreshToken(identityWithCredentials);
        Assert.assertNotNull(refreshToken);

        deleteKeyStore(tokenProvider.getKeyStorePath());
    }

    /**
     * Test verifies that given an expired access token, a new one is generated
     * with the utility method in the token provider.
     * @throws Exception
     */
    @Test
    public void testUpdatingExpiredAccessTokens() throws Exception {

        // Very short access token expiry time to make sure new access token gets issued
        WildFlyElytronTokenProvider tokenProvider = WildFlyElytronTokenProvider.builder()
                .setAccessTokenExpiryTime(1)
                .build();

        SecurityIdentity identity = fetchSecurityIdentity(tokenProvider);

        // Add access and refresh token. Verify they were both added.
        SecurityIdentity identityWithCredentials = TokenUtil.updateTokenCredentials(identity, tokenProvider);
        String firstAccessToken = TokenUtil.getAccessToken(identityWithCredentials);
        Assert.assertNotNull(firstAccessToken);

        // Wait until access token expires
        TimeUnit.SECONDS.sleep(2);

        // Update token credentials and verify new access token differs from old one
        SecurityIdentity identityWithUpdatedTokens = TokenUtil.updateTokenCredentials(identityWithCredentials, tokenProvider);
        String secondAccessToken = TokenUtil.getAccessToken(identityWithUpdatedTokens);
        Assert.assertNotNull(secondAccessToken);
        Assert.assertNotEquals(firstAccessToken, secondAccessToken);
    }

    private SecurityIdentity fetchSecurityIdentity(WildFlyElytronTokenProvider tokenProvider) throws Exception {
        FileSystemSecurityRealm fileSystemSecurityRealm = createSecurityRealm();

        SecurityDomain domain = SecurityDomain.builder().setDefaultRealmName(REALM_NAME).addRealm(REALM_NAME, fileSystemSecurityRealm).build()
                .setPermissionMapper(((permissionMappable, roles) -> LoginPermission.getInstance()))
                .setTokenProvider(tokenProvider)
                .build();
        ServerAuthenticationContext sac1 = domain.createNewAuthenticationContext();

        sac1.setAuthenticationName(USER);
        assertTrue(sac1.verifyEvidence(new PasswordGuessEvidence(PASSWORD.toCharArray())));
        assertTrue(sac1.authorize());
        sac1.succeed();

        return sac1.getAuthorizedIdentity();
    }

    private void generateUserKeyStore(String keyStoreLocation, String signingAlias, String password) throws Exception {
        generateUserKeyStore(keyStoreLocation, signingAlias, null, password);
    }

    private void generateUserKeyStore(String keystoreLocation, String signingAlias, String encryptionAlias, String password) throws Exception {
        File file = Paths.get(keystoreLocation).toFile();
        KeyStore keyStore = KeyStore.getInstance("JKS");
        // Create Signing KeyPair
        SelfSignedX509CertificateAndSigningKey certificateSigning =
                generateCertificate("cn=UserSigning");

        X509Certificate[] certificateChainSigning = {certificateSigning.getSelfSignedCertificate()};
        keyStore.load(null, null);
        keyStore.setKeyEntry(signingAlias, certificateSigning.getSigningKey(), password.toCharArray(), certificateChainSigning);

        if (encryptionAlias != null) {
            // Create Encryption Keypair
            SelfSignedX509CertificateAndSigningKey certificateEncryption =
                    generateCertificate("cn=UserEncryption");
            X509Certificate[] certificateChainEncryption = {certificateEncryption.getSelfSignedCertificate()};
            keyStore.setKeyEntry(encryptionAlias, certificateEncryption.getSigningKey(), password.toCharArray(), certificateChainEncryption);
        }

        keyStore.store(new FileOutputStream(file), password.toCharArray());
    }

    private SelfSignedX509CertificateAndSigningKey generateCertificate(String dn) {
        return SelfSignedX509CertificateAndSigningKey.builder()
                .setDn(new X500Principal(dn))
                .setKeySize(4096)
                .setKeyAlgorithmName("RSA")
                .build();
    }

    private void deleteKeyStore(Path path) {
        File file = path.toFile();
        if (file.exists()) {
            file.delete();
        }
    }

    private FileSystemSecurityRealm createSecurityRealm() throws Exception {
        FileSystemSecurityRealm realm = new FileSystemSecurityRealm(getRootPath(true));
        char[] password = PASSWORD.toCharArray();
        PasswordFactory factory = PasswordFactory.getInstance(ClearPassword.ALGORITHM_CLEAR);
        ClearPassword clearPassword = (ClearPassword) factory.generatePassword(new ClearPasswordSpec(password));
        addUser(realm, USER, clearPassword);
        return realm;
    }

    private Path getRootPath(boolean deleteIfExists) throws Exception {
        Path rootPath = Paths.get(getClass().getResource(File.separator).toURI())
                .resolve("filesystem-realm");

        if (rootPath.toFile().exists() && !deleteIfExists) {
            return rootPath;
        }

        return Files.walkFileTree(Files.createDirectories(rootPath), new SimpleFileVisitor<Path>() {
            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                Files.delete(file);
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult postVisitDirectory(Path dir, IOException exc) throws IOException {
                return FileVisitResult.CONTINUE;
            }
        });
    }

    private void addUser(ModifiableSecurityRealm realm, String userName, Password credential) throws RealmUnavailableException {
        ModifiableRealmIdentity realmIdentity = realm.getRealmIdentityForUpdate(new NamePrincipal(userName));
        realmIdentity.create();
        realmIdentity.setCredentials(Collections.singleton(new PasswordCredential(credential)));
        MapAttributes attributes = new MapAttributes();
        attributes.addAll("Roles", Arrays.asList("Employee", "Manager", "Admin"));
        realmIdentity.setAttributes(attributes);
        realmIdentity.dispose();
    }

}
