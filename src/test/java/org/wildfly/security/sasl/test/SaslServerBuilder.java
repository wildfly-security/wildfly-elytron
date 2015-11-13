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

import java.security.Permissions;
import java.security.spec.KeySpec;
import java.util.Map;

import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;

import org.junit.Assert;
import org.wildfly.security.auth.provider.SimpleMapBackedSecurityRealm;
import org.wildfly.security.auth.server.MechanismConfiguration;
import org.wildfly.security.auth.server.SaslAuthenticationFactory;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;
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
    //Server factory info
    private final Class<? extends SaslServerFactory> serverFactoryClass;
    private final String mechanismName;

    //Security domain info
    private String username;
    private Password password = NULL_PASSWORD;
    private String realmName = "mainRealm";
    private String defaultRealmName = realmName;
    private Map<String, Permissions> permissionsMap = null;

    //Server factory decorators
    private Map<String, Object> properties;
    private Tuple<String, byte[]> bindingTypeAndData;
    private String protocol;
    private String serverName;
    private X509TrustManager trustManager;
    private X509KeyManager keyManager;
    private Credential credential;
    private String algorithm;
    private boolean dontAssertBuiltServer;

    public SaslServerBuilder(Class<? extends SaslServerFactory> serverFactoryClass, String mechanismName) {
        this.serverFactoryClass = serverFactoryClass;
        this.mechanismName = mechanismName;
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

    public SaslServerBuilder setRealmName(String realmName) {
        Assert.assertNotNull(realmName);
        this.realmName = realmName;
        return this;
    }

    public SaslServerBuilder setDefaultRealmName(String realmName) {
        this.defaultRealmName = realmName;
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

    public SaslServerBuilder setTrustManager(final X509TrustManager trustManager) {
        this.trustManager = trustManager;
        return this;
    }

    public SaslServerBuilder setKeyManager(final X509KeyManager keyManager) {
        this.keyManager = keyManager;
        return this;
    }

    public SaslServerBuilder setCredential(final Credential credential, final String algorithmName) {
        this.credential = credential;
        this.algorithm = algorithmName;
        return this;
    }

    public SaslServerBuilder setDontAssertBuiltServer() {
        this.dontAssertBuiltServer = true;
        return this;
    }

    public SaslServer build() throws SaslException {
        final SecurityDomain.Builder domainBuilder = SecurityDomain.builder();
        final SimpleMapBackedSecurityRealm mainRealm = new SimpleMapBackedSecurityRealm();
        domainBuilder.addRealm(realmName, mainRealm);
        domainBuilder.setDefaultRealmName(defaultRealmName);

        if (username != null) {
            mainRealm.setPasswordMap(username, password);
        }

        if (permissionsMap != null) {
            domainBuilder.setPermissionMapper((principal, roles) -> {
                if (!permissionsMap.containsKey(principal.toString())) {
                    throw new IllegalStateException(principal.toString()+" unknown, known: "+permissionsMap.toString());
                }
                return permissionsMap.get(principal.toString());
            });
        }

        SecurityDomain domain = domainBuilder.build();
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
        builder.setSaslServerFactory(factory);
        builder.setSecurityDomain(domain);
        builder.addMechanism(mechanismName, MechanismConfiguration.EMPTY);
        final SaslServer server = builder.build().createMechanism(mechanismName);
        if (!dontAssertBuiltServer) {
            Assert.assertNotNull(server);
        }
        return server;
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

}
