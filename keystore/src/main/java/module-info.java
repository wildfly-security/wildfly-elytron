module org.wildfly.security.keystore {

    requires java.naming;
    requires org.wildfly.common;
    requires org.wildfly.security.provider.util;
    requires org.wildfly.security.util;
    requires org.wildfly.security.x500.cert;
    requires org.wildfly.security;
    requires static org.jboss.logging.annotations;
    requires static org.jboss.logging;
    requires static org.kohsuke.metainf_services;

    exports org.wildfly.security.keystore;

    provides java.security.Provider
        with org.wildfly.security.keystore.WildFlyElytronKeyStoreProvider;
}
