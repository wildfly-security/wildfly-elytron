module org.wildfly.security.sasl.digest {

    requires java.security.sasl;
    requires org.wildfly.common;
    requires org.wildfly.security.auth.server;
    requires org.wildfly.security.credential;
    requires org.wildfly.security.mechanism.digest;
    requires org.wildfly.security.mechanism;
    requires org.wildfly.security.provider.util;
    requires org.wildfly.security.sasl;
    requires org.wildfly.security.util;
    requires org.wildfly.security;
    requires static org.kohsuke.metainf_services;

    exports org.wildfly.security.sasl.digest;

    provides java.security.Provider
        with org.wildfly.security.sasl.digest.WildFlyElytronSaslDigestProvider;
    provides javax.security.sasl.SaslClientFactory
        with org.wildfly.security.sasl.digest.DigestClientFactory;
    provides javax.security.sasl.SaslServerFactory
        with org.wildfly.security.sasl.digest.DigestServerFactory;
}
