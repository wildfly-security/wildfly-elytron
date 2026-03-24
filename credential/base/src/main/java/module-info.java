module org.wildfly.security.credential {

    requires java.security.jgss;
    requires java.security.sasl;
    requires org.wildfly.common;
    requires org.wildfly.security.asn1;
    requires org.wildfly.security.keystore;
    requires org.wildfly.security.provider.util;
    requires org.wildfly.security.util;
    requires org.wildfly.security.x500;
    requires org.wildfly.security;
    requires static org.jboss.logging.annotations;
    requires static org.jboss.logging;
    requires static org.kohsuke.metainf_services;

    exports org.wildfly.security.credential;
    exports org.wildfly.security.credential.keystore;
    exports org.wildfly.security.evidence;
    exports org.wildfly.security.key;
    exports org.wildfly.security.password;
    exports org.wildfly.security.password.interfaces;
    exports org.wildfly.security.password.spec;
    exports org.wildfly.security.password.util;

    provides java.security.Provider
        with org.wildfly.security.key.WildFlyElytronKeyProvider,
            org.wildfly.security.password.WildFlyElytronPasswordProvider;
}
