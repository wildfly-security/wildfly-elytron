module org.wildfly.security.digest {

    requires org.wildfly.common;
    requires org.wildfly.security;
    requires static org.kohsuke.metainf_services;

    exports org.wildfly.security.digest;

    provides java.security.Provider
        with org.wildfly.security.digest.WildFlyElytronDigestProvider;
}
