package eu.unicore.security.wsutil;

import eu.unicore.security.SecurityTokens;

/**
 * Security session information, server side.
 * 
 * @author schuller
 */
public class SecuritySession {
	private final String sessionID;

	private final SecurityTokens tokens;

	private final long expires;

	private long lastAccessed;

	private String userKey;

	/**
	 * create a new security session
	 * @param sessionID - the session ID
	 * @param tokens - the security tokens used to create the session
	 * @param lifetime - the lifetime in millis
	 */
	public SecuritySession(String sessionID, SecurityTokens tokens, long lifetime){
		this.sessionID=sessionID;
		this.tokens = tokens;
		this.expires=System.currentTimeMillis()+lifetime;
		this.lastAccessed=System.currentTimeMillis();
	}

	/**
	 * get a COPY of the tokens stored for this session
	 */
	public SecurityTokens getTokens() {
		lastAccessed=System.currentTimeMillis();
		try{
			return this.tokens.clone();
		}
		catch(CloneNotSupportedException cne){
			return tokens;
		}
	}

	public boolean isExpired(){
		return expires<System.currentTimeMillis();
	}

	public String getSessionID() {
		return sessionID;
	}

	/**
	 * get the identifier of the user who "owns" the session
	 * @return
	 */
	public String getUserKey() {
		return userKey;
	}

	/**
	 * set the user identifier (e.g. effective client DN + IP)
	 * @param userKey
	 */
	public void setUserKey(String userKey) {
		this.userKey = userKey;
	}

	public long getLastAccessed(){
		return lastAccessed;
	}

	/**
	 * return the remaining lifetime in milliseconds
	 * @return
	 */
	public long getLifetime(){
		long lt = expires-System.currentTimeMillis();
		return lt>0 ? lt : 0;
	}
}
