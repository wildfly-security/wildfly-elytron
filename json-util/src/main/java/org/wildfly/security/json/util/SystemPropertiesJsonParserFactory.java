/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2020 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.wildfly.security.json.util;

import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.util.Collections;
import java.util.Map;
import java.util.Properties;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.io.IOContext;
import com.fasterxml.jackson.core.util.JsonParserDelegate;
import com.fasterxml.jackson.databind.MappingJsonFactory;

/**
 * Provides replacing of system properties for parsed values
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 * @since 1.14.0
 */
public class SystemPropertiesJsonParserFactory extends MappingJsonFactory {

    private static final Properties properties = new SystemEnvProperties();

    @Override
    protected JsonParser _createParser(InputStream in, IOContext ctxt) throws IOException {
        JsonParser delegate =  super._createParser(in, ctxt);
        return new SystemPropertiesAwareJsonParser(delegate);
    }

    @Override
    protected JsonParser _createParser(Reader r, IOContext ctxt) throws IOException {
        JsonParser delegate =  super._createParser(r, ctxt);
        return new SystemPropertiesAwareJsonParser(delegate);
    }

    @Override
    protected JsonParser _createParser(char[] data, int offset, int len, IOContext ctxt, boolean recyclable) throws IOException {
        JsonParser delegate =  super._createParser(data, offset, len, ctxt, recyclable);
        return new SystemPropertiesAwareJsonParser(delegate);
    }

    @Override
    protected JsonParser _createParser(byte[] data, int offset, int len, IOContext ctxt) throws IOException {
        JsonParser delegate =  super._createParser(data, offset, len, ctxt);
        return new SystemPropertiesAwareJsonParser(delegate);
    }

    public static class SystemPropertiesAwareJsonParser extends JsonParserDelegate {

        public SystemPropertiesAwareJsonParser(JsonParser d) {
            super(d);
        }

        @Override
        public String getText() throws IOException {
            String orig = super.getText();
            return StringPropertyReplacer.replaceProperties(orig, properties);
        }
    }

    private static class SystemEnvProperties extends Properties {

        private final Map<String, String> overrides;

        public SystemEnvProperties(Map<String, String> overrides) {
            this.overrides = overrides;
        }

        public SystemEnvProperties() {
            this.overrides = Collections.EMPTY_MAP;
        }

        @Override
        public String getProperty(String key) {
            if (overrides.containsKey(key)) {
                return overrides.get(key);
            } else if (key.startsWith("env.")) {
                return System.getenv().get(key.substring(4));
            } else {
                return System.getProperty(key);
            }
        }

        @Override
        public String getProperty(String key, String defaultValue) {
            String value = getProperty(key);
            return value != null ? value : defaultValue;
        }
    }
}
