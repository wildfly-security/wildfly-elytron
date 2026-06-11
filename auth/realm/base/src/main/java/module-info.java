module org.wildfly.security.auth.realm {

    requires java.xml.crypto;
    requires java.xml;
    requires org.wildfly.common;
    requires org.wildfly.security.auth.server;
    requires org.wildfly.security.auth;
    requires org.wildfly.security.credential;
    requires org.wildfly.security.encryption;
    requires org.wildfly.security.permission;
    requires org.wildfly.security.provider.util;
    requires org.wildfly.security.util;
    requires org.wildfly.security.x500;
    requires static org.jboss.logging.annotations;
    requires static org.jboss.logging;

    exports org.wildfly.security.auth.realm;
}
