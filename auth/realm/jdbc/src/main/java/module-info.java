module org.wildfly.security.auth.realm.jdbc {

    requires java.sql;
    requires org.wildfly.common;
    requires org.wildfly.security.auth.realm;
    requires org.wildfly.security.auth.server;
    requires org.wildfly.security.auth;
    requires org.wildfly.security.credential;
    requires org.wildfly.security.provider.util;
    requires org.wildfly.security.util;
    requires static org.jboss.logging.annotations;
    requires static org.jboss.logging;

    exports org.wildfly.security.auth.realm.jdbc;
    exports org.wildfly.security.auth.realm.jdbc.mapper;
}
