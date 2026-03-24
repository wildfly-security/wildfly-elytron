module org.wildfly.security.sasl.entity {

    requires java.security.sasl;
    requires org.wildfly.common;
    requires org.wildfly.security.asn1;
    requires org.wildfly.security.auth.server;
    requires org.wildfly.security.credential;
    requires org.wildfly.security.mechanism;
    requires org.wildfly.security.sasl;
    requires org.wildfly.security.x500;
    requires org.wildfly.security;
    requires static org.kohsuke.metainf_services;

    exports org.wildfly.security.sasl.entity;

    provides java.security.Provider
        with org.wildfly.security.sasl.entity.WildFlyElytronSaslEntityProvider;
    provides javax.security.sasl.SaslClientFactory
        with org.wildfly.security.sasl.entity.EntitySaslClientFactory;
    provides javax.security.sasl.SaslServerFactory
        with org.wildfly.security.sasl.entity.EntitySaslServerFactory;
}
