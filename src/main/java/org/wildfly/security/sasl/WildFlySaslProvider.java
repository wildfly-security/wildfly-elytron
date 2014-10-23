/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2014 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wildfly.security.sasl;

import static org.wildfly.security.sasl.anonymous.AbstractAnonymousFactory.ANONYMOUS;
import static org.wildfly.security.sasl.gssapi.AbstractGssapiFactory.GSSAPI;
import static org.wildfly.security.sasl.localuser.LocalUserSaslFactory.JBOSS_LOCAL_USER;
import static org.wildfly.security.sasl.md5digest.MD5DigestServerFactory.JBOSS_DIGEST_MD5;
import static org.wildfly.security.sasl.plain.PlainServerFactory.PLAIN;
import static org.wildfly.security.sasl.scram.Scram.SCRAM_SHA_1;
import static org.wildfly.security.sasl.scram.Scram.SCRAM_SHA_1_PLUS;
import static org.wildfly.security.sasl.scram.Scram.SCRAM_SHA_256;
import static org.wildfly.security.sasl.scram.Scram.SCRAM_SHA_256_PLUS;
import static org.wildfly.security.sasl.scram.Scram.SCRAM_SHA_384;
import static org.wildfly.security.sasl.scram.Scram.SCRAM_SHA_384_PLUS;
import static org.wildfly.security.sasl.scram.Scram.SCRAM_SHA_512;
import static org.wildfly.security.sasl.scram.Scram.SCRAM_SHA_512_PLUS;

import java.security.Provider;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import javax.security.sasl.SaslClientFactory;
import javax.security.sasl.SaslServerFactory;

import org.kohsuke.MetaInfServices;
import org.wildfly.security.Version;
import org.wildfly.security.sasl.anonymous.AnonymousClientFactory;
import org.wildfly.security.sasl.anonymous.AnonymousServerFactory;
import org.wildfly.security.sasl.gssapi.GssapiClientFactory;
import org.wildfly.security.sasl.gssapi.GssapiServerFactory;
import org.wildfly.security.sasl.localuser.LocalUserClientFactory;
import org.wildfly.security.sasl.localuser.LocalUserServerFactory;
import org.wildfly.security.sasl.plain.PlainServerFactory;
import org.wildfly.security.sasl.md5digest.MD5DigestClientFactory;
import org.wildfly.security.sasl.md5digest.MD5DigestServerFactory;
import org.wildfly.security.sasl.scram.ScramSaslClientFactory;
import org.wildfly.security.sasl.scram.ScramSaslServerFactory;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
@MetaInfServices(value = Provider.class)
public class WildFlySaslProvider extends Provider {

    private static final long serialVersionUID = 2819852358608732038L;

    private static final String INFO = "WildFly Elytron SASL Provider " + Version.getVersion();

    private static final String SASL_CLIENT_FACTORY = SaslClientFactory.class.getSimpleName();

    private static final String SASL_SERVER_FACTORY = SaslServerFactory.class.getSimpleName();

    /**
     * Construct a new instance.
     */
    public WildFlySaslProvider() {
        super("wildfly-sasl", 1.0, INFO);
        // NOTE: make sure that all client and server factories listed here also end up in the META-INF/services files.
        final List<String> noAliases = Collections.emptyList();
        final Map<String, String> noProperties = Collections.emptyMap();
        putService(new Service(this, SASL_CLIENT_FACTORY, ANONYMOUS, AnonymousClientFactory.class.getName(), noAliases, noProperties));
        putService(new Service(this, SASL_SERVER_FACTORY, ANONYMOUS, AnonymousServerFactory.class.getName(), noAliases, noProperties));
        putService(new Service(this, SASL_SERVER_FACTORY, PLAIN, PlainServerFactory.class.getName(), noAliases, noProperties));
        putService(new Service(this, SASL_SERVER_FACTORY, JBOSS_LOCAL_USER, LocalUserServerFactory.class.getName(), noAliases, noProperties));
        putService(new Service(this, SASL_CLIENT_FACTORY, JBOSS_LOCAL_USER, LocalUserClientFactory.class.getName(), noAliases, noProperties));
        putService(new Service(this, SASL_SERVER_FACTORY, GSSAPI, GssapiServerFactory.class.getName(), noAliases, noProperties));
        putService(new Service(this, SASL_CLIENT_FACTORY, GSSAPI, GssapiClientFactory.class.getName(), noAliases, noProperties));
        putService(new Service(this, SASL_CLIENT_FACTORY, JBOSS_DIGEST_MD5, MD5DigestClientFactory.class.getName(), noAliases, noProperties));
        putService(new Service(this, SASL_SERVER_FACTORY, JBOSS_DIGEST_MD5, MD5DigestServerFactory.class.getName(), noAliases, noProperties));
        putService(new Service(this, SASL_CLIENT_FACTORY, SCRAM_SHA_1, ScramSaslClientFactory.class.getName(), noAliases, noProperties));
        putService(new Service(this, SASL_CLIENT_FACTORY, SCRAM_SHA_1_PLUS, ScramSaslClientFactory.class.getName(), noAliases, noProperties));
        putService(new Service(this, SASL_CLIENT_FACTORY, SCRAM_SHA_256, ScramSaslClientFactory.class.getName(), noAliases, noProperties));
        putService(new Service(this, SASL_CLIENT_FACTORY, SCRAM_SHA_256_PLUS, ScramSaslClientFactory.class.getName(), noAliases, noProperties));
        putService(new Service(this, SASL_CLIENT_FACTORY, SCRAM_SHA_384, ScramSaslClientFactory.class.getName(), noAliases, noProperties));
        putService(new Service(this, SASL_CLIENT_FACTORY, SCRAM_SHA_384_PLUS, ScramSaslClientFactory.class.getName(), noAliases, noProperties));
        putService(new Service(this, SASL_CLIENT_FACTORY, SCRAM_SHA_512, ScramSaslClientFactory.class.getName(), noAliases, noProperties));
        putService(new Service(this, SASL_CLIENT_FACTORY, SCRAM_SHA_512_PLUS, ScramSaslClientFactory.class.getName(), noAliases, noProperties));
        putService(new Service(this, SASL_SERVER_FACTORY, SCRAM_SHA_1, ScramSaslServerFactory.class.getName(), noAliases, noProperties));
        putService(new Service(this, SASL_SERVER_FACTORY, SCRAM_SHA_1_PLUS, ScramSaslServerFactory.class.getName(), noAliases, noProperties));
        putService(new Service(this, SASL_SERVER_FACTORY, SCRAM_SHA_256, ScramSaslServerFactory.class.getName(), noAliases, noProperties));
        putService(new Service(this, SASL_SERVER_FACTORY, SCRAM_SHA_256_PLUS, ScramSaslServerFactory.class.getName(), noAliases, noProperties));
        putService(new Service(this, SASL_SERVER_FACTORY, SCRAM_SHA_384, ScramSaslServerFactory.class.getName(), noAliases, noProperties));
        putService(new Service(this, SASL_SERVER_FACTORY, SCRAM_SHA_384_PLUS, ScramSaslServerFactory.class.getName(), noAliases, noProperties));
        putService(new Service(this, SASL_SERVER_FACTORY, SCRAM_SHA_512, ScramSaslServerFactory.class.getName(), noAliases, noProperties));
        putService(new Service(this, SASL_SERVER_FACTORY, SCRAM_SHA_512_PLUS, ScramSaslServerFactory.class.getName(), noAliases, noProperties));
    }
}
