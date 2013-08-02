package eu.unicore.security.wsutil.client;

import java.util.Collections;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import eu.unicore.util.httpclient.SessionIDProvider;
import eu.unicore.util.httpclient.SessionIDProviderFactory;

/**
 * default implementation for dealing with session IDs
 * on the client side.<br/> 
 * 
 * NOTE: this only deals with a single Grid identity.<br/>
 * DO NOT USE this class if multiple Grid identities are used
 *
 * @author schuller
 */
public class SessionIDProviderImpl implements SessionIDProvider {

	private String sessionID;

	private String scope;
	
	private long lifetime;
	
	/**
	 * @param uri - the service URI
	 */
	public SessionIDProviderImpl(String uri){
		this.scope=extractServerID(uri);
	}

	/*
	 * extract the service independent part of a service URI
	 */
	private String extractServerID(String uri){
		try{
			//TODO better way?
			return uri.split("services")[0];
		}catch(Exception ex){
			return uri;
		}
	}

	@Override
	public String getSessionID() {
		if(sessionID==null){
			sessionID=sessionIDs.get(scope);
		}
		return sessionID;
	}

	@Override
	public void setSessionID(String sessionID) {
		this.sessionID=sessionID;
		if(sessionID!=null){
			sessionIDs.put(scope, sessionID);
		}
		else{
			sessionIDs.remove(scope);
		}
	}

	public void setScope(String scope){
		this.scope=scope;
	}
	
	public String getScope(){
		return scope;
	}

	public long getLifetime() {
		return lifetime;
	}

	public void setLifetime(long lifetime) {
		this.lifetime = lifetime;
	}

	// static map for server IDs and session IDs 
	private static final ConcurrentHashMap<String,String>sessionIDs = 
			new ConcurrentHashMap<String, String>();

	public static void store(String server, String sessionID){
		sessionIDs.put(server, sessionID);
	}

	public static String getSessionID(String server){
		return sessionIDs.get(server);
	}

	/**
	 * re-initialise mappings (e.g. after a client restart)
	 * @param mappings
	 */
	public static void putAll(Map<String,String>mappings){
		sessionIDs.putAll(mappings);
	}

	/**
	 * get the full map (e.g. for storing before a client stop) 
	 */
	public static Map<String,String> getAll(){
		return Collections.unmodifiableMap(sessionIDs);
	}
	
	/**
	 * remove all mappings (i.e. invalidate all sessions)
	 */
	public static void clearAll(){
		sessionIDs.clear();
	}
	
	private static final Factory factory = new Factory();
	
	/**
	 * returns a {@link SessionIDProviderFactory} that will 
	 * create {@link SessionIDProviderImpl} instances
	 */
	public static SessionIDProviderFactory Factory(){
		return factory;
	}
	
	public static class Factory implements SessionIDProviderFactory {

		@Override
		public SessionIDProvider get(String uri) {
			return new SessionIDProviderImpl(uri);
		}
		
	}
	
}
