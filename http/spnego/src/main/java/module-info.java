module org.wildfly.security.http.spnego {

    requires java.security.jgss;
    requires java.security.sasl;
    requires org.jboss.logging;
    requires org.wildfly.common;
    requires org.wildfly.security.auth.server;
    requires org.wildfly.security.auth;
    requires org.wildfly.security.credential;
    requires org.wildfly.security.http;
    requires org.wildfly.security.mechanism.gssapi;
    requires org.wildfly.security.mechanism;
    requires org.wildfly.security;
    requires static org.jboss.logging.annotations;
    requires static org.kohsuke.metainf_services;

    exports org.wildfly.security.http.spnego;

    provides java.security.Provider
        with org.wildfly.security.http.spnego.WildFlyElytronHttpSpnegoProvider;
    provides org.wildfly.security.http.HttpServerAuthenticationMechanismFactory
        with org.wildfly.security.http.spnego.SpnegoMechanismFactory;
}
