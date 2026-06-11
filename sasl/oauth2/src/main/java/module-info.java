module org.wildfly.security.sasl.oauth2 {

    requires java.security.sasl;
    requires org.wildfly.common;
    requires org.wildfly.security.mechanism.oauth2;
    requires org.wildfly.security.mechanism;
    requires org.wildfly.security.sasl;
    requires org.wildfly.security;
    requires static org.kohsuke.metainf_services;

    exports org.wildfly.security.sasl.oauth2;

    provides java.security.Provider
        with org.wildfly.security.sasl.oauth2.WildFlyElytronSaslOAuth2Provider;
    provides javax.security.sasl.SaslClientFactory
        with org.wildfly.security.sasl.oauth2.OAuth2SaslClientFactory;
    provides javax.security.sasl.SaslServerFactory
        with org.wildfly.security.sasl.oauth2.OAuth2SaslServerFactory;
}
