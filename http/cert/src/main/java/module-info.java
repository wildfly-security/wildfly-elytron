module org.wildfly.security.http.cert {

    requires org.wildfly.common;
    requires org.wildfly.security.auth.server;
    requires org.wildfly.security.credential;
    requires org.wildfly.security.http;
    requires org.wildfly.security.mechanism;
    requires org.wildfly.security.x500;
    requires org.wildfly.security;
    requires static org.kohsuke.metainf_services;

    exports org.wildfly.security.http.cert;

    provides java.security.Provider
        with org.wildfly.security.http.cert.WildFlyElytronHttpClientCertProvider;
    provides org.wildfly.security.http.HttpServerAuthenticationMechanismFactory
        with org.wildfly.security.http.cert.ClientCertMechanismFactory;
}
