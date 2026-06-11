module org.wildfly.security.auth.client {

    requires java.security.jgss;
    requires java.security.sasl;
    requires java.xml;
    requires org.wildfly.common;
    requires org.wildfly.security.asn1;
    requires org.wildfly.security.auth.server;
    requires org.wildfly.security.auth.util;
    requires org.wildfly.security.auth;
    requires org.wildfly.security.credential.source.impl;
    requires org.wildfly.security.credential.store;
    requires org.wildfly.security.credential;
    requires org.wildfly.security.keystore;
    requires org.wildfly.security.mechanism.gssapi;
    requires org.wildfly.security.mechanism;
    requires org.wildfly.security.password.impl;
    requires org.wildfly.security.permission;
    requires org.wildfly.security.provider.util;
    requires org.wildfly.security.sasl;
    requires org.wildfly.security.ssh.util;
    requires org.wildfly.security.ssl;
    requires org.wildfly.security.x500.cert;
    requires org.wildfly.security.x500;
    requires org.wildfly.security;
    requires wildfly.client.config;
    requires static jakarta.json;
    requires static org.jboss.logging.annotations;
    requires static org.jboss.logging;
    requires static org.jboss.modules;
    requires static org.kohsuke.metainf_services;

    exports org.wildfly.security.auth.client;
    exports org.wildfly.security.auth.client.credential;
    exports org.wildfly.security.auth.client.util;

    provides java.security.Provider
        with org.wildfly.security.auth.client.WildFlyElytronClientDefaultSSLContextProvider;
}
