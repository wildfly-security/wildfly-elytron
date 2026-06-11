module org.wildfly.security.auth.realm.ldap {

    requires java.naming;
    requires org.jboss.modules;
    requires org.wildfly.common;
    requires org.wildfly.security.auth.client;
    requires org.wildfly.security.auth.realm;
    requires org.wildfly.security.auth.server;
    requires org.wildfly.security.auth;
    requires org.wildfly.security.credential;
    requires org.wildfly.security.manager.action;
    requires org.wildfly.security.provider.util;
    requires org.wildfly.security.util;
    requires org.wildfly.security;
    requires static org.jboss.logging.annotations;
    requires static org.jboss.logging;

    exports org.wildfly.security.auth.realm.ldap;
}
