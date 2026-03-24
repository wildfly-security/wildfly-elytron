module org.wildfly.security {

    requires org.jboss.logging;
    requires org.wildfly.common;
    requires static org.jboss.logging.annotations;
    requires static org.kohsuke.metainf_services;

    exports org.wildfly.security;

    provides java.security.Provider
        with org.wildfly.security.WildFlyElytronHttpFormProvider,
            org.wildfly.security.WildFlyElytronHttpClientCertProvider,
            org.wildfly.security.WildFlyElytronProvider,
            org.wildfly.security.WildFlyElytronHttpBearerProvider,
            org.wildfly.security.WildFlyElytronHttpBasicProvider,
            org.wildfly.security.WildFlyElytronDigestProvider,
            org.wildfly.security.WildFlyElytronHttpDigestProvider,
            org.wildfly.security.WildFlyElytronHttpSpnegoProvider;
}
