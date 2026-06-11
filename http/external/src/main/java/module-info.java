module org.wildfly.security.http.external {

    requires java.security.sasl;
    requires org.wildfly.common;
    requires org.wildfly.security.auth.server;
    requires org.wildfly.security.http;
    requires org.wildfly.security.mechanism.http;
    requires org.wildfly.security.mechanism;
    requires org.wildfly.security;
    requires static org.kohsuke.metainf_services;

    exports org.wildfly.security.http.external;

    provides java.security.Provider
        with org.wildfly.security.http.external.WildFlyElytronHttpExternalProvider;
    provides org.wildfly.security.http.HttpServerAuthenticationMechanismFactory
        with org.wildfly.security.http.external.ExternalMechanismFactory;
}
