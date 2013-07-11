package eu.unicore.security.wsutil.client;

import java.util.Collections;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * default implementation for dealing with session IDs
 *
 * @author schuller
 */
public class SessionIDProviderImpl implements SessionIDProvider {

	private String sessionID;

	private final String serverID;

	/**
	 * @param uri - the service URI
	 */
	public SessionIDProviderImpl(String uri){
		this.serverID=extractServerID(uri);
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
			sessionID=sessionIDs.get(serverID);
		}
		return sessionID;
	}

	@Override
	public void setSessionID(String sessionID) {
		this.sessionID=sessionID;
		if(sessionID!=null){
			sessionIDs.put(serverID, sessionID);
		}
		else{
			sessionIDs.remove(serverID);
		}
	}

	public String getServerID(){
		return serverID;
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
	
	/**
	 * helper to retrieve the {@link SessionIDProvider} from a given proxy object
	 * @param proxy
	 * @return
	 */
	public static SessionIDProvider getSessionIDProvider(Object proxy){
		return (SessionIDProvider)WSClientFactory.getWSClient(proxy).getRequestContext().get(SessionIDProvider.KEY);
	}
	
	/**
	 * helper to set the {@link SessionIDProvider} for a given proxy object
	 * @param provider
	 * @param proxy
	 * @return
	 */
	public static void setSessionIDProvider(SessionIDProvider provider, Object proxy){
		WSClientFactory.getWSClient(proxy).getRequestContext().put(SessionIDProvider.KEY, provider);
	}
	
}
