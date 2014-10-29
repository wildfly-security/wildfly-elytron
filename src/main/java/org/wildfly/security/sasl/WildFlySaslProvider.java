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

import java.security.Provider;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.ServiceConfigurationError;
import java.util.ServiceLoader;

import javax.security.sasl.SaslClientFactory;
import javax.security.sasl.SaslServerFactory;

import org.kohsuke.MetaInfServices;
import org.wildfly.security.Version;

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
        final List<String> noAliases = Collections.emptyList();
        final Map<String, String> noProperties = Collections.emptyMap();
        final ClassLoader myClassLoader = WildFlySaslProvider.class.getClassLoader();
        final String myClassName = WildFlySaslProvider.class.getName();
        final String myPackageWithDot = myClassName.substring(0, myClassName.lastIndexOf('.') + 1);
        final ServiceLoader<SaslClientFactory> clientLoader = ServiceLoader.load(SaslClientFactory.class, myClassLoader);
        final Iterator<SaslClientFactory> clientIterator = clientLoader.iterator();
        final Map<String, String> props = Collections.singletonMap(WildFlySasl.MECHANISM_QUERY_ALL, "true");
        for (;;) try {
            if (! clientIterator.hasNext()) break;
            final SaslClientFactory factory = clientIterator.next();
            if (factory.getClass().getClassLoader() != myClassLoader) {
                continue;
            }
            final String className = factory.getClass().getName();
            if (!className.startsWith(myPackageWithDot)) {
                continue;
            }
            final String[] names = factory.getMechanismNames(props);
            for (String name : names) {
                putService(new Service(this, SASL_CLIENT_FACTORY, name, className, noAliases, noProperties));
            }
        } catch (ServiceConfigurationError | RuntimeException ignored) {}
        final ServiceLoader<SaslServerFactory> serverLoader = ServiceLoader.load(SaslServerFactory.class, myClassLoader);
        final Iterator<SaslServerFactory> serverIterator = serverLoader.iterator();
        for (;;) try {
            if (!(serverIterator.hasNext())) break;
            final SaslServerFactory factory = serverIterator.next();
            if (factory.getClass().getClassLoader() != myClassLoader) {
                continue;
            }
            final String className = factory.getClass().getName();
            if (!className.startsWith(myPackageWithDot)) {
                continue;
            }
            final String[] names = factory.getMechanismNames(props);
            for (String name : names) {
                putService(new Service(this, SASL_SERVER_FACTORY, name, className, noAliases, noProperties));
            }
        } catch (ServiceConfigurationError | RuntimeException ignored) {}
    }
}
