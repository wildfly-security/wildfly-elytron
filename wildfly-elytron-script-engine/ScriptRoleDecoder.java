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
