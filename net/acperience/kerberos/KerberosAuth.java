package net.acperience.kerberos;

import java.io.IOException;

import javax.security.auth.*;
import javax.security.auth.login.*;
import javax.security.auth.callback.*;

/**
 * An abstract wrapper class to perform Kerberos authentication using Java. 
 * To use this class, you must first perform some configuration as described 
 * at <a href="http://docs.oracle.com/javase/1.4.2/docs/guide/security/jgss/tutorials/AcnOnly.html#ConfigFile">this page</a>.
 *	
 * <br /><br />
 *	
 * An implementing class must implement the abstract methods described<ul>
 *	<li>{@linkplain #getPersistentSubject}: Used to see if a subject has been authenticated</li>
 *	<li>{@linkplain #storePersistentSubject}: Used to store a persistent subject upon successful login</li>
 *	<li>{@linkplain #destroyPersistentSubject}: Destroy a persistent subject upon logout</li>
 *	<li>{@linkplain #getUsername}: Used to get a username for authentication</li>
 *	<li>{@linkplain #getPassword}: Used to get a password for authentication</li></ul>
 *	 	
 * After constructing the object, to populate the necessary fields, call authenticate()
 *
 * @author Lawliet
 * @see <a href="http://www.bsg.co.za/web/guest/software_solutions_technical_solution_showcase_java_kerberos">Link</a> for documentation
 * @see <a href="https://github.com/lawliet89/ICCloudCoursework/blob/master/src/net/acperience/cloudplayer/MusicKerberos.java">Example impelentation</a>.
 */
public abstract class KerberosAuth implements CallbackHandler{
		
	protected String name;		// The name of the authentication LoginModule
	private LoginContext lc;		// Login Context
	private Subject subject;		// Logged in subject

	/** 
	 * Default constructor to do no configuration changes. Java will attempt to authenticate based on default settings. 
	 * 
	 * @param name Name of the LoginModule to use.
	 * @throws LoginException
	 * @throws SecurityException
	 * @see <a href="http://docs.oracle.com/javase/1.4.2/docs/guide/security/jgss/tutorials/AcnOnly.html#ConfigFile">Java Documentation</a>
	 */
	public KerberosAuth(String name)
		throws LoginException, SecurityException
	{
		this.name = name;
	}
	
	
	/**
	 * An overloaded constructor to provide a path to a JAAS Login configuration file along with the name of the LoginModule.
	 * @param name Name of LoginModule to use.
	 * @param authLoginConfig The path to a JAAS Configuration file. 
	 * @throws LoginException
	 * @throws SecurityException
	 * @see <a href="http://docs.oracle.com/javase/1.4.2/docs/guide/security/jgss/tutorials/AcnOnly.html#ConfigFile">Java Documentation</a>
	 */
	public KerberosAuth(String name, String authLoginConfig)
			throws LoginException, SecurityException
	{
		this(name);
		
		System.setProperty("java.security.auth.login.config", authLoginConfig);
	}
	
	
	/**
	 * An overloaded constructor to provide a path to a JAAS Login Configuration file, name of LoginModule and a path to a Kerberos Configuration file.
	 * @param name Name of the LoginModule to use.
	 * @param authLoginConfig Path to a JAAS Configuration file.
	 * @param krb5Config Path to a Kerberos Authentication file
	 * @throws LoginException
	 * @throws SecurityException
	 * @see <a href="http://docs.oracle.com/javase/1.4.2/docs/guide/security/jgss/tutorials/AcnOnly.html#ConfigFile">Java Documentation</a>
	 */
	public KerberosAuth(String name, String authLoginConfig, String krb5Config)
			throws LoginException, SecurityException
	{
		this(name, authLoginConfig);
		
		System.setProperty("java.security.krb5.conf", krb5Config);
	}
	
	/**
	 * An overloaded consturctor to provide a LoginModule name, a path to a JAAS configuration file along with
	 * the Kerberos realm and Kerberos Key distribution center.
	 * @param name Name of LoginModule
	 * @param authLoginConfig Path to JAAS Configuration
	 * @param krbRealm Kerberos Realm to use
	 * @param krbKdc Kerberos Key distribution center
	 * @throws LoginException
	 * @throws SecurityException
	 */
	public KerberosAuth(String name, String authLoginConfig, String krbRealm, String krbKdc)
			throws LoginException, SecurityException
	{
		this(name, authLoginConfig);
		
		System.setProperty("java.security.krb5.realm", krbRealm);
		System.setProperty("java.security.krb5.kdc", krbKdc);
	}

	/**
	 * Gets an authenticated subject. Remember to call {@linkplain #authenticate()} first to populate the necessary data in the object.
	 * @return the authenticated subject
	 */
	public Subject getSubject() {
		return subject;
	}
	
	/**
	 * Handle login callbacks - implemented as required by CallbackHandler
	 * This is used by Java's Kerberos Login module. Do not call this normally.
	 * 
	 * @param callbacks The Callback object provided by Java's Login module.
	 */
	@Override
	public void handle(Callback[] callbacks)
            throws IOException, UnsupportedCallbackException{
		for (Callback current : callbacks){
			if (current instanceof NameCallback){
				NameCallback nc = (NameCallback) current;
				nc.setName(getUsername());
			}
			else if (current instanceof PasswordCallback){
				PasswordCallback pc = (PasswordCallback) current;
				pc.setPassword(getPassword().toCharArray());
			}
			else{
				throw new UnsupportedCallbackException(current, "Unsupported callback");
			}
		}
	}
	
	/**
	 * Creates a LoginContext based on settings
	 */
	protected void createLoginContext()
			throws LoginException, SecurityException
	{
		lc = new LoginContext(name,this);
	}
	
	/**
	 * @return LoginContext object
	 * @throws LoginException
	 * @throws SecurityException
	 */
	protected LoginContext getLoginContext()
			throws LoginException, SecurityException
	{
		if (lc == null) createLoginContext();
		return lc;
	}
	
	/**
	 * Check if we have a subject authenticated. 
	 * Remember to call {@linkplain #authenticate()} first to populate the necessary data in the object.
	 * 
	 * @return whether a user has been authenticated
	 */
	public boolean isAuthenticated(){
		return subject != null;
	}

	/**
	 * Authenticates and populates the subject field of the class<br /><br />
	 * 
	 * Method will first attempt to load a persistent subject. <br />
	 * Failing that, will attempt to load a subject from the LoginContext <br />
	 * If that fails, depending on whether doLogin is set to true or not, will perform a login<br />
	 * 
	 * @param doLogin Set to true to perform a login
	 * @throws LoginException
	 */
	public void authenticate(boolean doLogin)
		throws LoginException
	{
		// Get persistent subject
		subject = getPersistentSubject();
		if (subject != null)
			return;
		
		// Get subject from LC
		subject = getLoginContext().getSubject();
		
		if (subject != null)
			return;
		
		if (doLogin)
			login();
	}
	
	/**
	 * Convenience method to {@linkplain #authenticate(boolean)} with the parameter set to true. <br />
	 * Authenticates and populates the subject field of the class<br /><br />
	 * 
	 * Method will first attempt to load a persistent subject. <br />
	 * Failing that, will attempt to load a subject from the LoginContext <br />
	 * If that fails, method will perform a login<br />
	 *
	 */
	public void authenticate()
			throws LoginException, SecurityException
	{
		authenticate(true);
	}
	
	/**
	 * Performs a login. Method will populate the data via a call to {@linkplain #authenticate()} after login is complete.
	 */
	public void login()
		throws LoginException
	{
		getLoginContext().login();
		storePersistentSubject(lc.getSubject());
		
		// Let's repopulate
		authenticate(false);
	}
	
	/**
	 * Performs a logout. Method will populate the data via a call to {@linkplain #authenticate()} after login is complete.
	 */
	public void logout()
		throws LoginException
	{
		// Check if LoginContext has a subject
		if (getLoginContext().getSubject() != null)
			getLoginContext().logout();
		destroyPersistentSubject();
		
		// Let's repopulate
		authenticate(false);
	}
	
	/**
	 * Override this method to allow the class to retrieve any stored authenticated subjects. <br />
	 * If no one has been authenticated, return NULL and the class will attempt to authenticate <br />
	 * If not using persistent subjects, just override an empty method.
	 * 
	 * @return The subject stored in some persistent storage or NULL if none
	 */
	protected abstract Subject getPersistentSubject();
	
	/**
	 * Store a persistent subject. Called after a successful login attempt. <br />
	 * If not storing, just override an empty method
	 */
	protected abstract void storePersistentSubject(Subject subject);
	
	/**
	 * Destroys a persistent subject upon successful logout attempt. <br />
	 * If not using persistent subject, override an empty method.
	 */
	protected abstract void destroyPersistentSubject();
	
	/**
	 * Override this method to allow the class to get a username for authentication purposes if necessary
	 * 
	 * @return Username for authentication
	 */
	protected abstract String getUsername();
	
	/**
	 * Override this method to allow the class to get a password for authentication purposes if necessary
	 * 
	 * @return Password for authentication
	 */
	protected abstract String getPassword();
}
