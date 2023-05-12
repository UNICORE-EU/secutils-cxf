package eu.unicore.security.wsutil;

import javax.xml.namespace.QName;


/**
 * constant definitions related to security sessions
 *  
 * @author B. Schuller
 * @author K. Benedyczak
 */
public class SecuritySessionUtils
{
	//header namespace
	public static final String SESSION_HDR_NS="http://www.unicore.eu/unicore/ws";

	//header element name
	public static final String SESSION_HEADER="SecuritySession";

	public final static QName headerQName=new QName(SESSION_HDR_NS,SESSION_HEADER);

	public final static QName idQName=new QName(SESSION_HDR_NS,"ID");
	public final static QName ltQName=new QName(SESSION_HDR_NS,"Lifetime");

	/**
	 * Client side: context key of a url of a destination endpoint
	 */
	public static final String SESSION_TARGET_URL="unicore-security-session-target-url";
	
	/**
	 * Server side: used to store the session ID in the security tokens
	 */
	public static final String SESSION_ID_KEY="unicore-security-session-id";

	/**
	 * Server and client side. On the server side used to mark that the security tokens were taken 
	 * from an existing session. On client side marks that session is used for the outgoing call and the value is 
	 * the session id. 
	 */
	public static final String REUSED_MARKER_KEY="reused-unicore-security-session";
	
	/**
	 * HTTP header used to pass the session ID between client and server and vice versa
	 * (RESTful use)
	 */
	public final static String SESSION_ID_HEADER = "X-UNICORE-SecuritySession";
	
	/**
	 * HTTP header used to pass the session lifetime to the client
	 * (RESTful use)
	 */
	public final static String SESSION_LIFETIME_HEADER = "X-UNICORE-SecuritySession-Lifetime";

}
