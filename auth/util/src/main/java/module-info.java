module org.wildfly.security.auth.util {

    requires java.xml;
    requires org.apache.sshd.common;
    requires org.jboss.logging;
    requires org.wildfly.common;
    requires org.wildfly.security.auth.server;
    requires org.wildfly.security.auth;
    requires org.wildfly.security.credential;
    requires org.wildfly.security.x500;
    requires static org.jboss.logging.annotations;

    exports org.wildfly.security.auth.util;
}
