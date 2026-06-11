module org.wildfly.security.sasl.localuser {

    requires java.security.sasl;
    requires org.wildfly.common;
    requires org.wildfly.security.auth.server;
    requires org.wildfly.security.manager.action;
    requires org.wildfly.security.mechanism;
    requires org.wildfly.security.sasl;
    requires org.wildfly.security;
    requires static org.kohsuke.metainf_services;

    exports org.wildfly.security.sasl.localuser;

    provides java.security.Provider
        with org.wildfly.security.sasl.localuser.WildFlyElytronSaslLocalUserProvider;
    provides javax.security.sasl.SaslClientFactory
        with org.wildfly.security.sasl.localuser.LocalUserClientFactory;
    provides javax.security.sasl.SaslServerFactory
        with org.wildfly.security.sasl.localuser.LocalUserServerFactory;
}
