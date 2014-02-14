/*
 * Copyright (c) 2013 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.security.wsutil;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.log4j.Logger;

import eu.unicore.security.SecurityTokens;
import eu.unicore.util.Log;

/**
 * Responsible for security session storage.
 * 
 * Current implementation stores sessions in memory only.
 * 
 * This class is thread safe.
 * 
 * @author K. Benedyczak
 * @author B. Schuller
 */
public class SecuritySessionStore
{
	private static final Logger log = Log.getLogger(Log.SECURITY, SecuritySessionStore.class);
	private final static int DEF_MAX_SESSIONS_PER_USER = 5;
	private final static long CLEANUP_INTERVAL = 1000*60; 

	/**
	 * store security tokens keyed by security session ID
	 */
	private final Map<String, SecuritySession> sessions = new HashMap<String, SecuritySession>();

	/**
	 * stores number of sessions per user (identified as effective DN + Client IP)
	 * If this exceeds a threshold, the least-recently-used session is removed
	 */
	private final Map<String, AtomicInteger> sessionsPerUser = new HashMap<String, AtomicInteger>();

	/**
	 * When the sessions were cleaned the last time.
	 */
	private long lastCleanup = 0; 

	private final int maxPerUser;

	public SecuritySessionStore()
	{
		this(DEF_MAX_SESSIONS_PER_USER);
	}

	public SecuritySessionStore(int maxPerUser)
	{
		this.maxPerUser = maxPerUser;
	}

	public synchronized void storeSession(SecuritySession session, SecurityTokens tokens)
	{
		sessions.put(session.getSessionID(), session);
		String userKey=getUserKey(tokens);
		session.setUserKey(userKey);
		AtomicInteger i = getOrCreateSessionCounter(userKey);
		int sessions=i.incrementAndGet();
		if(log.isDebugEnabled()){
			log.debug("Created new security session <"+session.getSessionID()+" for <"+userKey+
					"> will expire in " + (session.getLifetime()/1000.0) + "s");
		}

		if (lastCleanup + CLEANUP_INTERVAL < System.currentTimeMillis())
			expelExpiredSessions();

		if (maxPerUser > 0 && sessions > maxPerUser)
			expelLRUSession(userKey);
	}

	public synchronized SecuritySession getSession(String sessionID)
	{
		return sessions.get(sessionID);
	}

	private String getUserKey(SecurityTokens tokens){
		return tokens.getEffectiveUserName()+"@"+tokens.getClientIP();
	}

	// retrieve the session counter
	private synchronized AtomicInteger getOrCreateSessionCounter(String userKey){
		AtomicInteger i=sessionsPerUser.get(userKey);
		if (i==null) {
			i=new AtomicInteger(0);
			sessionsPerUser.put(userKey, i);
		}
		return i;
	}

	private void decrementUserSessionCounter(String userKey){
		AtomicInteger i=getOrCreateSessionCounter(userKey);
		int sessions=i.decrementAndGet();
		if(log.isDebugEnabled()){
			log.debug("Sessions for "+userKey+" : "+sessions);
		}
	}

	/**
	 * Removes all expired sessions.
	 */
	private void expelExpiredSessions() {
		Iterator<Map.Entry<String, SecuritySession>> iterator = sessions.entrySet().iterator();
		while (iterator.hasNext()) {
			SecuritySession session = iterator.next().getValue();
			if(session.isExpired()){
				iterator.remove();
				decrementUserSessionCounter(session.getUserKey());
			}
		}
		lastCleanup = System.currentTimeMillis();
	}

	/**
	 * Removes the LRU session for the given user key.
	 * @param key
	 */
	private void expelLRUSession(String key){
		SecuritySession lru=null;
		for(SecuritySession session: sessions.values()){
			if(lru==null || lru.getLastAccessed()>session.getLastAccessed()){
				lru=session;
			}
		}
		if (lru!=null){
			if(log.isDebugEnabled()){
				log.debug("Removing LRU session for "+key);
			}
			if(null!=sessions.remove(lru.getSessionID())){
				decrementUserSessionCounter(key);
			}
		}
	}
}
