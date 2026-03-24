module org.wildfly.security.auth.realm.token {

    requires org.wildfly.common;
    requires org.wildfly.security.auth.server;
    requires org.wildfly.security.auth;
    requires org.wildfly.security.credential;
    requires org.wildfly.security.json.util;
    requires org.wildfly.security.x500.cert;
    requires static jakarta.json;
    requires static org.jboss.logging.annotations;
    requires static org.jboss.logging;

    exports org.wildfly.security.auth.realm.token;
    exports org.wildfly.security.auth.realm.token.validator;
}
