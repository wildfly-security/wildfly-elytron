module org.wildfly.security.sasl.scram {

    requires java.security.sasl;
    requires org.wildfly.common;
    requires org.wildfly.security.auth.server;
    requires org.wildfly.security.mechanism.scram;
    requires org.wildfly.security.mechanism;
    requires org.wildfly.security.provider.util;
    requires org.wildfly.security.sasl;
    requires org.wildfly.security.util;
    requires org.wildfly.security;
    requires static org.kohsuke.metainf_services;

    exports org.wildfly.security.sasl.scram;

    provides java.security.Provider
        with org.wildfly.security.sasl.scram.WildFlyElytronSaslScramProvider;
    provides javax.security.sasl.SaslClientFactory
        with org.wildfly.security.sasl.scram.ScramSaslClientFactory;
    provides javax.security.sasl.SaslServerFactory
        with org.wildfly.security.sasl.scram.ScramSaslServerFactory;
}
