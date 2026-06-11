module org.wildfly.security.http.digest {

    requires java.security.sasl;
    requires org.wildfly.common;
    requires org.wildfly.security.auth.server;
    requires org.wildfly.security.credential;
    requires org.wildfly.security.http;
    requires org.wildfly.security.mechanism.digest;
    requires org.wildfly.security.mechanism;
    requires org.wildfly.security.provider.util;
    requires org.wildfly.security.util;
    requires org.wildfly.security;
    requires static org.kohsuke.metainf_services;

    exports org.wildfly.security.http.digest;

    provides java.security.Provider
        with org.wildfly.security.http.digest.WildFlyElytronHttpDigestProvider;
    provides org.wildfly.security.http.HttpServerAuthenticationMechanismFactory
        with org.wildfly.security.http.digest.DigestMechanismFactory;
}
