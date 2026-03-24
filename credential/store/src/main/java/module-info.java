module org.wildfly.security.credential.store {

    requires org.wildfly.common;
    requires org.wildfly.security.asn1;
    requires org.wildfly.security.auth.server;
    requires org.wildfly.security.auth;
    requires org.wildfly.security.credential;
    requires org.wildfly.security.encryption;
    requires org.wildfly.security.permission;
    requires org.wildfly.security.provider.util;
    requires org.wildfly.security.util;
    requires org.wildfly.security.x500;
    requires org.wildfly.security;
    requires static org.jboss.logging.annotations;
    requires static org.jboss.logging;
    requires static org.kohsuke.metainf_services;

    exports org.wildfly.security.credential.store;
    exports org.wildfly.security.credential.store.impl;

    provides java.security.Provider
        with org.wildfly.security.credential.store.WildFlyElytronCredentialStoreProvider;
}
