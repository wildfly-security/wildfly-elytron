module org.wildfly.security.sasl.gs2 {

    requires java.security.jgss;
    requires java.security.sasl;
    requires org.wildfly.common;
    requires org.wildfly.security.asn1;
    requires org.wildfly.security.auth.server;
    requires org.wildfly.security.credential;
    requires org.wildfly.security.manager.action;
    requires org.wildfly.security.mechanism.gssapi;
    requires org.wildfly.security.mechanism;
    requires org.wildfly.security.sasl;
    requires org.wildfly.security;
    requires static org.kohsuke.metainf_services;

    exports org.wildfly.security.sasl.gs2;

    provides java.security.Provider
        with org.wildfly.security.sasl.gs2.WildFlyElytronSaslGs2Provider;
    provides javax.security.sasl.SaslClientFactory
        with org.wildfly.security.sasl.gs2.Gs2SaslClientFactory;
    provides javax.security.sasl.SaslServerFactory
        with org.wildfly.security.sasl.gs2.Gs2SaslServerFactory;
}
