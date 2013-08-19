package eu.unicore.security.wsutil;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import eu.unicore.security.SecurityTokens;

/**
 * security session information
 * 
 * @author schuller
 */
public class SecuritySession {
	private final String sessionID;

	private final byte[] securityTokensBin;

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
		this.securityTokensBin = serialize(tokens);
		this.expires=System.currentTimeMillis()+lifetime;
		this.lastAccessed=System.currentTimeMillis();
	}

	/**
	 * get a COPY of the tokens stored for this session
	 */
	public SecurityTokens getTokens() {
		lastAccessed=System.currentTimeMillis();
		return deserialize(securityTokensBin);
	}

	private byte[] serialize(SecurityTokens tokens) {
		try{
			ByteArrayOutputStream bos=new ByteArrayOutputStream();
			ObjectOutputStream oos=new ObjectOutputStream(bos);
			synchronized (tokens) {
				oos.writeObject(tokens);
				oos.close();
			}
			return bos.toByteArray();
		}catch(Exception ex){
			throw new RuntimeException(ex);
		}
	}

	private SecurityTokens deserialize(byte[] binary) {
		try{
			ByteArrayInputStream is=new ByteArrayInputStream(binary);
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
