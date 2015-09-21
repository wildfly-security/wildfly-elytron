/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2015, Red Hat, Inc., and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
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
import java.util.Map;

import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;

import org.junit.Assert;
import org.wildfly.security.auth.provider.FileSystemSecurityRealm;
import org.wildfly.security.auth.provider.SimpleMapBackedSecurityRealm;
import org.wildfly.security.auth.server.ModifiableRealmIdentity;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.sasl.util.ChannelBindingSaslServerFactory;
import org.wildfly.security.sasl.util.PropertiesSaslServerFactory;
import org.wildfly.security.sasl.util.ProtocolSaslServerFactory;
import org.wildfly.security.sasl.util.ServerNameSaslServerFactory;

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

    //Server factory decorators
    private Map<String, Object> properties;
    private Tuple<String, byte[]> bindingTypeAndData;
    private String protocol;
    private String serverName;
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
        this.password = factory.generatePassword(keySpec);
        Assert.assertNotNull(this.password);
        return this;
    }

    public SaslServerBuilder setPassword(Password password) {
        this.password = password;
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
        this.permissionsMap = permissionsMap;
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
        SaslServer server = securityDomain.createNewAuthenticationContext().createSaslServer(factory, mechanismName);
        if (!dontAssertBuiltServer) {
            Assert.assertNotNull(server);
        }
        return server;
    }


    private SecurityDomain createSecurityDomain() throws IOException {
        final SecurityDomain.Builder domainBuilder = SecurityDomain.builder();
        if (!modifiableRealm) {
            final SimpleMapBackedSecurityRealm mainRealm = new SimpleMapBackedSecurityRealm();
            domainBuilder.addRealm(realmName, mainRealm);
            if (username != null) {
                mainRealm.setPasswordMap(username, password);
            }
        } else {
            final Path root = Paths.get(".", "target", "test-domains", String.valueOf(System.currentTimeMillis())).normalize();
            Files.createDirectories(root);
            final FileSystemSecurityRealm mainRealm = new FileSystemSecurityRealm(root);
            domainBuilder.addRealm(realmName, mainRealm);

            ModifiableRealmIdentity realmIdentity = mainRealm.createRealmIdentity(username);
            realmIdentity.create();
            realmIdentity.setCredentials(Collections.singletonList(password));

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


        if (permissionsMap != null) {
            domainBuilder.setPermissionMapper((principal, roles) -> {
                if (!permissionsMap.containsKey(principal.toString())) {
                    throw new IllegalStateException(principal.toString() + " unknown, known: " + permissionsMap.toString());
                }
                return permissionsMap.get(principal.toString());
            });
        }

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