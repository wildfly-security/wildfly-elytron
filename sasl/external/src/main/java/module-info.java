module org.wildfly.security.sasl.external {

    requires java.security.sasl;
    requires org.wildfly.common;
    requires org.wildfly.security.auth.server;
    requires org.wildfly.security.mechanism;
    requires org.wildfly.security.sasl;
    requires org.wildfly.security;
    requires static org.kohsuke.metainf_services;

    exports org.wildfly.security.sasl.external;

    provides java.security.Provider
        with org.wildfly.security.sasl.external.WildFlyElytronSaslExternalProvider;
    provides javax.security.sasl.SaslClientFactory
        with org.wildfly.security.sasl.external.ExternalSaslClientFactory;
    provides javax.security.sasl.SaslServerFactory
        with org.wildfly.security.sasl.external.ExternalSaslServerFactory;
}
