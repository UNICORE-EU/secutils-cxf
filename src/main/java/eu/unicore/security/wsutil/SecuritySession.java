package eu.unicore.security.wsutil;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

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

	public SecurityTokens getTokens(){
		lastAccessed=System.currentTimeMillis();
		return tokens;
	}
	
	/**
	 * get a COPY of the tokens stored for this session
	 * 
	 * TODO there is a potential race condition when
	 * the first connection is still creating the new sec tokens,
	 * but new connections are already accessing it
	 */
	public SecurityTokens getTokenCopy(){
		lastAccessed=System.currentTimeMillis();
		return copy(tokens);
	}

	private SecurityTokens copy(SecurityTokens tokens){
		try{
			ByteArrayOutputStream bos=new ByteArrayOutputStream();
			ObjectOutputStream oos=new ObjectOutputStream(bos);
			synchronized (tokens) {
				oos.writeObject(tokens);
				oos.close();
			}
			ByteArrayInputStream is=new ByteArrayInputStream(bos.toByteArray());
			ObjectInputStream ois=new ObjectInputStream(is);
			Object result = ois.readObject();
			ois.close();
			return (SecurityTokens)result;
		}catch(Exception ex){
			throw new RuntimeException(ex);
		}
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
