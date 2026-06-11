module org.wildfly.security.http.util.sso {

    requires org.wildfly.common;
    requires org.wildfly.security.auth.server;
    requires org.wildfly.security.auth;
    requires org.wildfly.security.http.util;
    requires org.wildfly.security.http;
    requires static org.jboss.logging.annotations;
    requires static org.jboss.logging;

    exports org.wildfly.security.http.util.sso;
}
