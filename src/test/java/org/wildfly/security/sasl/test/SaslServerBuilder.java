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
package org.wildfly.security.sasl.test;

import static org.wildfly.security.sasl.test.BaseTestCase.obtainSaslServerFactory;

import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Permissions;
import java.security.spec.KeySpec;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;

import org.junit.Assert;
import org.wildfly.security.auth.permission.LoginPermission;
import org.wildfly.security.auth.realm.FileSystemSecurityRealm;
import org.wildfly.security.auth.realm.SimpleMapBackedSecurityRealm;
import org.wildfly.security.auth.realm.SimpleRealmEntry;
import org.wildfly.security.auth.server.IdentityLocator;
import org.wildfly.security.auth.server.MechanismConfiguration;
import org.wildfly.security.auth.server.MechanismConfigurationSelector;
import org.wildfly.security.auth.server.MechanismRealmConfiguration;
import org.wildfly.security.auth.server.ModifiableRealmIdentity;
import org.wildfly.security.auth.server.SaslAuthenticationFactory;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.permission.PermissionVerifier;
import org.wildfly.security.sasl.WildFlySasl;
import org.wildfly.security.sasl.util.AvailableRealmsSaslServerFactory;
import org.wildfly.security.sasl.util.ChannelBindingSaslServerFactory;
import org.wildfly.security.sasl.util.CredentialSaslServerFactory;
import org.wildfly.security.sasl.util.KeyManagerCredentialSaslServerFactory;
import org.wildfly.security.sasl.util.PropertiesSaslServerFactory;
import org.wildfly.security.sasl.util.ProtocolSaslServerFactory;
import org.wildfly.security.sasl.util.ServerNameSaslServerFactory;
import org.wildfly.security.sasl.util.TrustManagerSaslServerFactory;

/**
 * @author Kabir Khan
 */
public class SaslServerBuilder {
    public static final String DEFAULT_REALM_NAME = "mainRealm";

    //Server factory info
    private final Class<? extends SaslServerFactory> serverFactoryClass;
    private final String mechanismName;

    //Security domain info
    private String username;
    private Password password = NULL_PASSWORD;
    private String realmName = DEFAULT_REALM_NAME;
    private String defaultRealmName = realmName;
    private boolean modifiableRealm;
    private Map<String, Permissions> permissionsMap = null;
    private Map<String, SimpleRealmEntry> passwordMap;
    private Map<String, SecurityRealm> realms = new HashMap<String, SecurityRealm>();
    private Map<String, MechanismRealmConfiguration> mechanismRealms = new LinkedHashMap<>();

    //Server factory decorators
    private Map<String, Object> properties;
    private Tuple<String, byte[]> bindingTypeAndData;
    private String protocol;
    private String serverName;
    private X509TrustManager trustManager;
    private X509KeyManager keyManager;
    private Credential credential;
    private boolean dontAssertBuiltServer;

    private SecurityDomain securityDomain;
    private BuilderReference<Closeable> closeableReference;
    private BuilderReference<SecurityDomain> securityDomainReference;

    public SaslServerBuilder(Class<? extends SaslServerFactory> serverFactoryClass, String mechanismName) {
        this.serverFactoryClass = serverFactoryClass;
        this.mechanismName = mechanismName;
    }

    public SaslServerBuilder copy(boolean keepDomain) {
        if (securityDomain == null && keepDomain) {
            throw new IllegalStateException("Can only copy a built server when keeping domain");
        }
        SaslServerBuilder copy = new SaslServerBuilder(serverFactoryClass, mechanismName);
        copy.username = username;
        copy.password = password;
        copy.realmName = realmName;
        copy.defaultRealmName = defaultRealmName;
        copy.modifiableRealm = modifiableRealm;
        if (permissionsMap != null) {
            copy.permissionsMap = new HashMap<>(permissionsMap);
        }
        if (properties != null) {
            copy.properties = new HashMap<>(properties);
        }
        copy.bindingTypeAndData = bindingTypeAndData;
        copy.protocol = protocol;
        copy.serverName = serverName;
        copy.dontAssertBuiltServer = dontAssertBuiltServer;
        if (keepDomain) {
            copy.securityDomain = securityDomain;
        }
        return copy;
    }


    public SaslServerBuilder setUserName(String username) {
        this.username = username;
        return this;
    }

    public SaslServerBuilder setPassword(char[] password) throws Exception {
        Assert.assertNotNull(password);
        setPassword(ClearPassword.ALGORITHM_CLEAR, new ClearPasswordSpec(password));
        return this;
    }

    public SaslServerBuilder setPassword(final String algorithm, final KeySpec keySpec) throws Exception {
        Assert.assertNotNull(algorithm);
        Assert.assertNotNull(password);
        final PasswordFactory factory = PasswordFactory.getInstance(algorithm);
        return setPassword(factory.generatePassword(keySpec));
    }

    public SaslServerBuilder setPassword(Password password) {
        Assert.assertNotNull(this.password);
        this.password = password;
        return this;
    }

    public SaslServerBuilder setPasswordMap(final Map<String, String> passwordMap) throws Exception {
        Assert.assertNotNull(passwordMap);
        this.passwordMap = new HashMap<String, SimpleRealmEntry>(passwordMap.size());
        passwordMap.forEach((userName, passwordStr) -> {
            final Password password;
            if (passwordStr == null) {
                password = NULL_PASSWORD;
            } else {
                try {
                    final PasswordFactory factory = PasswordFactory.getInstance(ClearPassword.ALGORITHM_CLEAR);
                    password = factory.generatePassword(new ClearPasswordSpec(passwordStr.toCharArray()));
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
            Assert.assertNotNull(password);
            this.passwordMap.put(userName, new SimpleRealmEntry(Collections.singletonList(new PasswordCredential(password))));
        });
        return this;
    }

    public SaslServerBuilder setRealmName(String realmName) {
        Assert.assertNotNull(realmName);
        this.realmName = realmName;
        return this;
    }

    public SaslServerBuilder setDefaultRealmName(String realmName) {
        this.defaultRealmName = realmName;
        return this;
    }

    public SaslServerBuilder setModifiableRealm() {
        this.modifiableRealm = true;
        return this;
    }

    public SaslServerBuilder setProperties(Map<String, Object> properties) {
        Assert.assertNotNull(properties);
        this.properties = properties;
        return this;
    }

    public SaslServerBuilder setPermissionsMap(Map<String, Permissions> permissionsMap) {
        Assert.assertNotNull(permissionsMap);
        this.permissionsMap = new HashMap<String, Permissions>(permissionsMap);
        return this;
    }

    public SaslServerBuilder setChannelBinding(final String bindingType, byte[] bindingData) {
        Assert.assertNotNull(bindingType);
        Assert.assertNotNull(bindingData);
        bindingTypeAndData = new Tuple<>(bindingType, bindingData);
        return this;
    }

    public SaslServerBuilder setProtocol(final String protocol) {
        this.protocol = protocol;
        return this;
    }

    public SaslServerBuilder setServerName(final String serverName) {
        this.serverName = serverName;
        return this;
    }

    public SaslServerBuilder setTrustManager(final X509TrustManager trustManager) {
        this.trustManager = trustManager;
        return this;
    }

    public SaslServerBuilder setKeyManager(final X509KeyManager keyManager) {
        this.keyManager = keyManager;
        return this;
    }

    public SaslServerBuilder setCredential(final Credential credential) {
        this.credential = credential;
        return this;
    }

    public SaslServerBuilder addRealm(final String realmName, final SecurityRealm securityRealm) {
        Assert.assertNotNull(realmName);
        Assert.assertNotNull(securityRealm);
        realms.put(realmName, securityRealm);
        return this;
    }

    public SaslServerBuilder addMechanismRealm(final String realmName) {
        Assert.assertNotNull("realmName", realmName);
        final MechanismRealmConfiguration.Builder builder = MechanismRealmConfiguration.builder();
        builder.setRealmName(realmName);
        mechanismRealms.put(realmName, builder.build());
        return this;
    }

    public SaslServerBuilder setDontAssertBuiltServer() {
        this.dontAssertBuiltServer = true;
        return this;
    }

    public SaslServerBuilder registerCloseableReference(BuilderReference<Closeable> closeableReference) {
        this.closeableReference = closeableReference;
        return this;
    }

    public SaslServerBuilder registerSecurityDomainReference(BuilderReference<SecurityDomain> securityDomainReference) {
        this.securityDomainReference = securityDomainReference;
        return this;
    }

    public SaslServer build() throws IOException {
        if (securityDomain == null) {
            securityDomain = createSecurityDomain();
        }
        if (securityDomainReference != null) {
            securityDomainReference.setReference(securityDomain);
        }
        SaslServerFactory factory = obtainSaslServerFactory(serverFactoryClass);
        if (properties != null && properties.size() > 0) {
            if (properties.containsKey(WildFlySasl.REALM_LIST)) {
                factory = new AvailableRealmsSaslServerFactory(factory);
            }
            factory = new PropertiesSaslServerFactory(factory, properties);
        }
        if (bindingTypeAndData != null) {
            factory = new ChannelBindingSaslServerFactory(factory, bindingTypeAndData.key, bindingTypeAndData.value);
        }
        if (protocol != null) {
            factory = new ProtocolSaslServerFactory(factory, protocol);
        }
        if (serverName != null) {
            factory = new ServerNameSaslServerFactory(factory, serverName);
        }
        if (trustManager != null) {
            factory = new TrustManagerSaslServerFactory(factory, trustManager);
        }
        if (keyManager != null) {
            factory = new KeyManagerCredentialSaslServerFactory(factory, keyManager);
        }
        if (credential != null) {
            factory = new CredentialSaslServerFactory(factory, credential);
        }
        final SaslAuthenticationFactory.Builder builder = SaslAuthenticationFactory.builder();
        builder.setFactory(factory);
        builder.setSecurityDomain(securityDomain);
        final MechanismConfiguration.Builder mechBuilder = MechanismConfiguration.builder();
        for (MechanismRealmConfiguration realmConfiguration : mechanismRealms.values()) {
            mechBuilder.addMechanismRealm(realmConfiguration);
        }
        builder.setMechanismConfigurationSelector(MechanismConfigurationSelector.constantSelector(mechBuilder.build()));
        final SaslServer server = builder.build().createMechanism(mechanismName);
        if (!dontAssertBuiltServer) {
            Assert.assertNotNull(server);
        }
        return server;
    }

    private SecurityDomain createSecurityDomain() throws IOException {
        final SecurityDomain.Builder domainBuilder = SecurityDomain.builder();
        if (! modifiableRealm) {
            final SimpleMapBackedSecurityRealm mainRealm = new SimpleMapBackedSecurityRealm();
            realms.put(realmName, mainRealm);
            realms.forEach((name, securityRealm) -> {
                domainBuilder.addRealm(name, securityRealm).build();
            });

            if (passwordMap != null) {
                mainRealm.setPasswordMap(passwordMap);
            } else if (username != null) {
                mainRealm.setPasswordMap(username, password);
            }
        } else {
            final Path root = Paths.get(".", "target", "test-domains", String.valueOf(System.currentTimeMillis())).normalize();
            Files.createDirectories(root);
            final FileSystemSecurityRealm mainRealm = new FileSystemSecurityRealm(root);
            realms.put(realmName, mainRealm);
            realms.forEach((name, securityRealm) -> {
                domainBuilder.addRealm(name, securityRealm).build();
            });

            ModifiableRealmIdentity realmIdentity = mainRealm.getRealmIdentityForUpdate(IdentityLocator.fromName(username));
            realmIdentity.create();
            realmIdentity.setCredentials(Collections.singletonList(new PasswordCredential(password)));
            realmIdentity.dispose();

            if (closeableReference != null) {
                closeableReference.setReference(new Closeable() {
                    @Override
                    public void close() throws IOException {
                        delete(root.getParent().toFile());
                    }
                    private void delete(File file) {
                        if (file.isDirectory()) {
                            for (File child : file.listFiles()) {
                                delete(child);
                            }
                        }
                        file.delete();
                    }
                });
            }
        }

        domainBuilder.setDefaultRealmName(defaultRealmName);

        if (permissionsMap == null) {
            permissionsMap = new HashMap<>();
        }
        domainBuilder.setPermissionMapper((permissionMappable, roles) -> {
            final PermissionVerifier v = PermissionVerifier.from(new LoginPermission());
            final Permissions permissions = permissionsMap.get(permissionMappable.getPrincipal().toString());
            return permissions == null ? v : v.or(PermissionVerifier.from(permissions));
        });

        return domainBuilder.build();
    }

    private static class Tuple<K, V> {
        private final K key;
        private final V value;

        public Tuple(K key, V value) {
            this.key = key;
            this.value = value;
        }
    }

    private static Password NULL_PASSWORD = new Password() {
        @Override
        public String getAlgorithm() {
            return null;
        }

        @Override
        public String getFormat() {
            return null;
        }

        @Override
        public byte[] getEncoded() {
            return new byte[0];
        }
    };

    public static class BuilderReference<T> {
        private T ref;

        private void setReference(T ref) {
            this.ref = ref;
        }

        public T getReference() {
            return ref;
        }
    }
}
