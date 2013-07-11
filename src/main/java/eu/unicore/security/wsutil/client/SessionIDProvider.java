package eu.unicore.security.wsutil.client;

public interface SessionIDProvider {

	/**
	 * used to store the session ID provider in the message exchange
	 */
	public static final String KEY="unicore-security-session-id-provider";

	public String getSessionID();
	
	public void setSessionID(String sessionID);

	public void setLifetime(long lifetime);
	
	public long getLifetime();

	public void setScope(String scope);

	public String getScope();
}
