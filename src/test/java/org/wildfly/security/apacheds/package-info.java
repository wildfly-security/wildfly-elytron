/*
 * JBoss, Home of Professional Open Source
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

/**
 * Package to hold utility classes as required to run suites of tests using ApacheDS.
 *
 * It is my intention that all utility classes related to using ApacheDS move to their own
 * project as multiple projects now use ApacheDS for testing, bearing that in mind anything
 * added to this package should be considered 'portable'.
 *
 * At the same time this package is the only place where ApacheDS classes should be accessed,
 * if anything else needs to be accessed it should be wrapped here.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
package org.wildfly.security.apacheds;