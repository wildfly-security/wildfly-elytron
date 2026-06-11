module org.wildfly.security.x500.principal {

    requires org.wildfly.security.auth.server;
    requires org.wildfly.security.auth;
    requires org.wildfly.security.credential;
    requires org.wildfly.security.x500;
    requires static org.jboss.logging.annotations;
    requires static org.jboss.logging;

    exports org.wildfly.security.x500.principal;
}
