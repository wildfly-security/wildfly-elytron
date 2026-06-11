module org.wildfly.security.mechanism.gssapi {

    requires java.security.jgss;
    requires org.jboss.logging;
    requires org.wildfly.common;
    requires org.wildfly.security.auth.server;
    requires org.wildfly.security.credential;
    requires org.wildfly.security.manager.action;
    requires org.wildfly.security;
    requires static org.jboss.logging.annotations;

    exports org.wildfly.security.mechanism.gssapi;
}
