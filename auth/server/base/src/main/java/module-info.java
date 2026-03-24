module org.wildfly.security.auth.server {

    requires java.security.sasl;
    requires org.jboss.logging;
    requires org.wildfly.common;
    requires org.wildfly.security.asn1;
    requires org.wildfly.security.auth;
    requires org.wildfly.security.credential;
    requires org.wildfly.security.permission;
    requires org.wildfly.security.util;
    requires org.wildfly.security.x500;
    requires org.wildfly.security;
    requires static jboss.logmanager;
    requires static org.jboss.logging.annotations;
    requires static org.jboss.threads;

    exports org.wildfly.security.auth.callback;
    exports org.wildfly.security.auth.permission;
    exports org.wildfly.security.auth.server;
    exports org.wildfly.security.auth.server.event;
    exports org.wildfly.security.auth.ssl;
    exports org.wildfly.security.authz;
    exports org.wildfly.security.cache;
    exports org.wildfly.security.credential.source;
}
