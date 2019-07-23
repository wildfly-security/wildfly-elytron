/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2019 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.script.engine;

import javax.script.Invocable;
import javax.script.ScriptEngineManager;
import javax.script.ScriptException;
import java.util.HashMap;
import java.util.Set;

public class ScriptRoleDecoder implements RoleDecoder {
    ScriptEngineManager manager  = new ScriptEngineManager();
    javax.script.ScriptEngine jsEngine = manager.getEngineByName("nashorn");
    Invocable invocable = (Invocable) jsEngine;
    String pathToJSFile;
    HashMap<String, Set<String>> roleMap;
    ScriptRoleDecoder(String pathToJSFile) throws ScriptException { //path to JS file to be specified while object creation
        roleMap = new HashMap<>();  //populate the HashMap beforehand as required
        this.pathToJSFile = pathToJSFile;
        jsEngine.eval(pathToJSFile);    //call the file using eval() method
    }
    Roles decodeRoles(AuthorizationIdentity authorizationIdentity) throws ScriptException, NoSuchMethodException { //returns Roles object
        return decodeRolesHelper(authorizationIdentity,roleMap);

    }
    Roles decodeRolesHelper(AuthorizationIdentity authorizationIdentity, HashMap<String, Set<String>> roleMap) throws ScriptException, NoSuchMethodException { //helper function to use custom method written in JS
        String attributeKey = authorizationIdentity.getAttributes().getFirst(“department”); //key attribute corresponding to the desired attribute kind
        return new Roles().fromSet(invocable.invokeFunction("returnSetOfRoles",attributeKey,roleMap)); //JS method by the name "returnSetOfRoles" has to be present in the file taking arguments as a String and Java Map.
    }

}
