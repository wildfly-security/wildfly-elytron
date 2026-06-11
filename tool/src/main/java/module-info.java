module org.wildfly.security.tool {

    requires jboss.logmanager;
    requires org.aesh.readline;
    requires org.apache.commons.cli;
    requires org.apache.sshd.common;
    requires org.jboss.logging;
    requires org.wildfly.common;
    requires org.wildfly.security.auth.realm;
    requires org.wildfly.security.auth.server;
    requires org.wildfly.security.auth.util;
    requires org.wildfly.security.auth;
    requires org.wildfly.security.credential.store;
    requires org.wildfly.security.credential;
    requires org.wildfly.security.encryption;
    requires org.wildfly.security.keystore;
    requires org.wildfly.security.password.impl;
    requires org.wildfly.security.provider.util;
    requires org.wildfly.security.ssh.util;
    requires org.wildfly.security.util;
    requires org.wildfly.security.x500.cert;
    requires org.wildfly.security;
    requires slf4j.jboss.logmanager;
    requires static org.apache.commons.lang3;
    requires static org.jboss.logging.annotations;

    exports org.wildfly.security.tool;
    exports org.wildfly.security.tool.help;
}
