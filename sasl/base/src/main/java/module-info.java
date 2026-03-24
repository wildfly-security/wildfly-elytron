module org.wildfly.security.sasl {

    requires java.security.jgss;
    requires java.security.sasl;
    requires org.jboss.logging;
    requires org.wildfly.common;
    requires org.wildfly.security.auth.server;
    requires org.wildfly.security.auth;
    requires org.wildfly.security.credential;
    requires org.wildfly.security.mechanism;
    requires org.wildfly.security.provider.util;
    requires org.wildfly.security.ssl;
    requires org.wildfly.security.util;
    requires org.wildfly.security.x500;
    requires org.wildfly.security;
    requires static org.jboss.logging.annotations;

    exports org.wildfly.security.sasl;
    exports org.wildfly.security.sasl.util;
}
