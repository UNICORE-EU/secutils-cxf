package eu.unicore.security.wsutil;

import eu.unicore.security.SecurityTokens;

public class SecuritySession {

	private final String sessionID;
	
	private final SecurityTokens tokens;
	
	private long lastAccessed;
	
	private String userKey;
	
	// milliseconds of inactivity before session is invalidated
	private long lifetime = 0;
			
	public SecuritySession(String sessionID, SecurityTokens tokens, long lifetime){
		this.sessionID=sessionID;
		this.tokens=tokens;
		this.lifetime=lifetime;
		this.lastAccessed=System.currentTimeMillis();
	}
	
	// TODO return a copy!
	public SecurityTokens getTokens(){
		lastAccessed=System.currentTimeMillis();
		return tokens;
	}
	
	public boolean isExpired(){
		return lifetime>0 && lastAccessed+lifetime<System.currentTimeMillis();
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
	
	public long getLifetime(){
		return lifetime;
	}
	
}
