module org.wildfly.security.http {

    requires jakarta.servlet;
    requires java.security.jgss;
    requires org.wildfly.common;
    requires org.wildfly.security.auth.server;
    requires org.wildfly.security.credential;
    requires static org.jboss.logging.annotations;
    requires static org.jboss.logging;

    exports org.wildfly.security.http;
    exports org.wildfly.security.http.impl;
}
