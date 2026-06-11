module org.wildfly.security.sasl.anonymous {

    requires java.security.sasl;
    requires org.wildfly.common;
    requires org.wildfly.security.auth.server;
    requires org.wildfly.security.auth;
    requires org.wildfly.security.mechanism;
    requires org.wildfly.security.sasl;
    requires org.wildfly.security;
    requires static org.kohsuke.metainf_services;

    exports org.wildfly.security.sasl.anonymous;

    provides java.security.Provider
        with org.wildfly.security.sasl.anonymous.WildFlyElytronSaslAnonymousProvider;
    provides javax.security.sasl.SaslClientFactory
        with org.wildfly.security.sasl.anonymous.AnonymousClientFactory;
    provides javax.security.sasl.SaslServerFactory
        with org.wildfly.security.sasl.anonymous.AnonymousServerFactory;
}
