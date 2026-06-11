module org.wildfly.security.audit {

    requires java.logging;
    requires org.wildfly.common;
    requires org.wildfly.security.auth.server;
    requires static jakarta.json;
    requires static jboss.logmanager;
    requires static org.jboss.logging.annotations;
    requires static org.jboss.logging;

    exports org.wildfly.security.audit;
}
