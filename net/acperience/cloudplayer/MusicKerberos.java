package net.acperience.cloudplayer;

import java.io.IOException;
import java.io.PrintWriter;
import java.security.Principal;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import net.acperience.kerberos.KerberosAuth;

import org.jets3t.service.S3Service;
import org.jets3t.service.S3ServiceException;
import org.jets3t.service.model.S3Bucket;

/**
 * An implementation of {@link KerberosAuth} specific to this application.
 * <br /><br />
 * Persistent storage of authenticated user is accomplished by storing a serialized version of the authenticated Subject in the HttpSession.
 * One instance of the class is instantiated with each HTTP request and should be destroyed upon the completion
 * of that HTTP request.
 * 
 * <br /><br />
 * The default Kerberos configuration is found on linux machines in DoC at /etc/krb5.conf <br />
 * The realm to use is IC.AC.UK. The KDCs can be found by running dig -t SRV _kerberos._tcp.ic.ac.uk<br /><br />
 * <br /><br />
 * Use the factory method {@linkplain #createLoginContext()} to get an instance of the class.
 * @author Lawliet
 *
 */
public class MusicKerberos extends KerberosAuth {
	
	private static final String PERSISTENT_NAME = "MusicKerberosSubject";
	private static final String PERSISTENT_USER_ID_NAME = "UserID";
	private static final String FORM_USERID_NAME = "userId";
	private static final String FORM_PASSWORD_NAME = "password";
	private static final String KERBEROS_REALM = "IC.AC.UK";
	
	private static final String AUTH_BASE = "/WEB-INF/conf/";
	private static final String LOGIN_CONF = AUTH_BASE + "jaas.conf";
	private static final String KRB5_CONF = AUTH_BASE + "krb5.conf";
	private static final String AUTH_ATTRIBUTE = "CloudMusicAuth";	
	
	private HttpSession session;
	private HttpServletRequest request;
	private HttpServletResponse response;	// Debugging purposes
	private S3Bucket bucket;
	private S3Service s3Service;
	
	/**
	 * Set S3Service to be used.
	 * @param s3Service the s3Service to set
	 */
	public void setS3Service(S3Service s3Service) {
		this.s3Service = s3Service;
	}
	
	
	/**
	 * Provides the necessary configuration for instantiating the class.
	 * @param name Name of LoginMoudle to use.
	 * @param authLoginConfig Path to a JAAS configuration file
	 * @param krb5Config Path to a Kerberos Authentication file
	 * @param request The HTTP Request object to obtain HttpSession information.
	 * @throws LoginException
	 * @throws SecurityException
	 */
	private MusicKerberos(String name, String authLoginConfig, String krb5Config, HttpServletRequest request)
			throws LoginException, SecurityException {
		// Call super to initialise
		super(name, authLoginConfig, krb5Config);
		this.request = request;
		this.session = request.getSession();
	}

	/* (non-Javadoc)
	 * @see net.acperience.cloudplayer.KerberosAuth#getPersistentSubject()
	 */
	@Override
	protected Subject getPersistentSubject() {
		// See if we can get a subject from the HttpSession
		Object persistent = session.getAttribute(PERSISTENT_NAME);
		if (persistent == null)
			return null;
		if (persistent instanceof Subject)
			return (Subject) persistent;
		
		return null;
	}

	/* (non-Javadoc)
	 * @see net.acperience.cloudplayer.KerberosAuth#storePersistentSubject()
	 */
	@Override
	protected void storePersistentSubject(Subject subject) {
		session.setAttribute(PERSISTENT_NAME, subject);
	}

	/* (non-Javadoc)
	 * @see net.acperience.cloudplayer.KerberosAuth#destroyPersistentSubject()
	 */
	@Override
	protected void destroyPersistentSubject() {
		session.removeAttribute(PERSISTENT_NAME);
		session.removeAttribute(PERSISTENT_USER_ID_NAME);
	}

	/* (non-Javadoc)
	 * @see net.acperience.cloudplayer.KerberosAuth#getUsername()
	 */
	@Override
	protected String getUsername() {
		
		return request.getParameter(FORM_USERID_NAME);
	}

	/* (non-Javadoc)
	 * @see net.acperience.cloudplayer.KerberosAuth#getPassword()
	 */
	@Override
	protected String getPassword() {
		return request.getParameter(FORM_PASSWORD_NAME);
	}
	
	/**
	 * Returns the user ID of the user that has been authenticated
	 * @return The College User ID of the user that has been authenticated. If the user has not been authenticated, returns null
	 */
	public String getUserId(){
		
		Subject subject = getSubject();
		if (subject == null)
			return null;
		
		// Check to see if we have stored the User ID already
		
		Object cache = session.getAttribute(PERSISTENT_USER_ID_NAME);
		if (cache instanceof String){
			return (String) cache;
		}
		
		//Get a list of principals
		Set<Principal> principals = subject.getPrincipals();
		String userId = null;
		for (Principal principal : principals){
			String[] result = principal.getName().split("@");
			if (result[1].equals(KERBEROS_REALM)){
				userId = result[0];
				break;
			}
		}
		userId = userId.toLowerCase();
		session.setAttribute(PERSISTENT_USER_ID_NAME, userId);
		return userId;
	}
	
	/**
	 * Returns the hash of the User ID or null if user is not logged in
	 * @return Returns the hash of the User ID or null if user is not logged in
	 */
	public String getUserIdHash(){
		String id = getUserId();
		if (id == null)
			return null;
		return MusicUtility.sha1(id);
	}
	
	/**
	 * Returns the name of the bucket for the logged in user, or null if not logged in.
	 * @return Returns the name of the bucket for the logged in user, or null if not logged in.
	 */
	public String getUserBucketName(){
		String id = getUserIdHash();
		if (id == null)
			return null;
		
		return "ywc110-cloud-" + id;
	}
	
	/**
	 * @return Returns the user's bucket. If it does not exist, attempts to create.
	 */
	public S3Bucket getUserBucket() throws S3ServiceException{
		if (bucket != null)
			return bucket;
		String name = getUserBucketName();
		if (name == null)
			return null;
		bucket = s3Service.getOrCreateBucket(name);
		return bucket;
	}
		

	/**
	 * Sets response object
	 * @param response
	 */
	public void setResponse(HttpServletResponse response) {
		this.response = response;
	}
	/**
	 * Write a message to output. Debugging purposes
	 * @param message
	 */
	public void writeResponse(String message){
		try {
			PrintWriter out = response.getWriter();
			out.println(message);
		} catch (IOException e) {
			e.printStackTrace();
		}
		
	}

	/**
	 * Creates a MusicKeberos object to get authenticated user data based on the HttpRequest
	 * 
	 * @param request Request to contain the necessary user context information
	 * @param context The HttpServlet calling the method
	 * @return An instantiated object specific to the HTTP Request
	 * @throws LoginException
	 * @throws SecurityException
	 */
	public static MusicKerberos createMusicKerberos(HttpServletRequest request, HttpServlet context)
		throws LoginException, SecurityException {
		// We will store a cache of the object for each HTTP Request
		Object cache = request.getAttribute(AUTH_ATTRIBUTE);
		if (cache != null){
			if (cache instanceof MusicKerberos)
				return (MusicKerberos) cache;
		}
		MusicKerberos obj = new MusicKerberos(AUTH_ATTRIBUTE,
				context.getServletContext().getRealPath(LOGIN_CONF),
				context.getServletContext().getRealPath(KRB5_CONF),
				request);
		// Attempt to authenticate and populate
		obj.authenticate(false);
		
		request.setAttribute(AUTH_ATTRIBUTE, obj);
		return obj;
	}
}
