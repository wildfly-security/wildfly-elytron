/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.util;

import org.wildfly.security.authz.Attributes;
import org.wildfly.security.authz.MapAttributes;

import javax.json.JsonArray;
import javax.json.JsonObject;
import javax.json.JsonString;
import javax.json.JsonValue;

/**
 * Utilities for JSON manipulation.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class JsonUtil {

    /**
     * Returns a {@link Attributes} instance based on the given {@link JsonObject}.
     *
     * @param claims a json object with the claims to extract
     * @return an {@link Attributes} instance with attributes from the given json object
     */
    public static Attributes toAttributes(JsonObject claims) {
        return claims.entrySet().stream().reduce(new MapAttributes(), (mapAttributes, entry) -> {
            String claimName = entry.getKey();
            JsonValue claimValue = entry.getValue();

            if (JsonValue.ValueType.ARRAY.equals(claimValue.getValueType())) {
                JsonArray jsonArray = claims.getJsonArray(claimName);
                jsonArray.forEach(arrayValue -> mapAttributes.addLast(claimName, asString(arrayValue)));
            } else {
                mapAttributes.addLast(claimName, asString(claimValue));
            }

            return mapAttributes;
        }, (mapAttributes, mapAttributes2) -> mapAttributes);
    }

    private static String asString(JsonValue value) {
        if (JsonValue.ValueType.STRING.equals(value.getValueType())) {
            return ((JsonString) value).getString();
        }

        return value.toString();
    }
}
