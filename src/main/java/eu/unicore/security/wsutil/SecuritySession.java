package eu.unicore.security.wsutil;

import eu.unicore.security.SecurityTokens;

public class SecuritySession {

	private final String sessionID;
	
	private final SecurityTokens tokens;
	
	private final long expires;
	
	private long lastAccessed;
	
	private String userKey;
			
	public SecuritySession(String sessionID, SecurityTokens tokens, long lifetime){
		this.sessionID=sessionID;
		this.tokens=tokens;
		this.expires=System.currentTimeMillis()+lifetime;
		this.lastAccessed=System.currentTimeMillis();
	}
	
	// TODO return a copy!
	public SecurityTokens getTokens(){
		lastAccessed=System.currentTimeMillis();
		return tokens;
	}
	
	public boolean isExpired(){
		return expires<System.currentTimeMillis();
	}
	
	public String getSessionID() {
		return sessionID;
	}
	
	public String getUserKey() {
		return userKey;
	}

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
