module org.wildfly.security.dynamic.ssl {

    requires org.wildfly.common;
    requires org.wildfly.security.auth.client;
    requires static jboss.logmanager;
    requires static org.jboss.logging.annotations;
    requires static org.jboss.logging;
    requires static org.kohsuke.metainf_services;

    exports org.wildfly.security.dynamic.ssl;

    provides org.wildfly.security.dynamic.ssl.DynamicSSLContextSPI
        with org.wildfly.security.dynamic.ssl.DynamicSSLContextImpl;
}
