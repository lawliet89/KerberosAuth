package net.acperience.kerberos;

import javax.security.auth.*;
import javax.security.auth.login.*;
import com.sun.security.auth.callback.TextCallbackHandler;
import java.security.Principal;
import java.util.Set;

/**
 * This JaasTest application attempts to authenticate a user
 * and reports whether or not the authentication was successful.
 */
public class JaasTest {

    public static void main(String[] args) {

        // Obtain a LoginContext, needed for authentication. Tell it 
        // to use the LoginModule implementation specified by the 
        // entry named "JaasSample" in the JAAS login configuration 
        // file and to also use the specified CallbackHandler.
        LoginContext lc = null;
        try {
            lc = new LoginContext("JaasSample", new TextCallbackHandler());
        } catch (LoginException le) {
            System.err.println("Cannot create LoginContext. "
                + le.getMessage());
            System.exit(-1);
        } catch (SecurityException se) {
            System.err.println("Cannot create LoginContext. "
                + se.getMessage());
            System.exit(-1);
        } 

        try {

            // attempt authentication
            lc.login();

        } catch (LoginException le) {

            System.err.println("Authentication failed:");
            System.err.println("  " + le.getMessage());
            System.exit(-1);

        }

        System.out.println("Authentication succeeded!");
        // Get a list of private and public credentials
        System.out.println("Now public:");
        Subject subject = lc.getSubject();
        Set<Object> publicCredentials = subject.getPublicCredentials();
        for (Object obj : publicCredentials){
        	System.out.println(obj.toString());
        }
        System.out.println("Now private:");
        Set<Object> privateCredentials = subject.getPrivateCredentials();
        for (Object obj : privateCredentials){
        	System.out.println(obj.toString());
        }
        System.out.println("Now principals:");
        Set<Principal> principals = subject.getPrincipals();
        for (Principal current : principals){
        	System.out.println(current.getName());
        }
    }
}
/*
    class MyCallbackHandler implements CallbackHandler {

       String user = 'xxxx';
       String password = 'yyyyy';   // much better to read these from a secure file..

       public void handle(Callback[] callbacks)
          throws IOException, UnsupportedCallbackException {

          for (int i = 0; i < callbacks.length; i++) {

             if (callbacks[i] instanceof NameCallback) {
                NameCallback nc = (NameCallback)callbacks[i];
                nc.setName(username);

             } else if (callbacks[i] instanceof PasswordCallback) {
                PasswordCallback pc = (PasswordCallback)callbacks[i];
                char passwordchars[] = password.toCharArray();
                pc.setPassword( passwordchars );
                for (int i = 0; i < password.length(); i++) passwordchars[i] = '*'; 

             } else throw new UnsupportedCallbackException
                (callbacks[i], "Unrecognised callback");

          }
       }
    }
    
    */