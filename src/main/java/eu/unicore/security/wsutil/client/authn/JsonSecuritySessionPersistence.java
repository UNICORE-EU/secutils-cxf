/*
 * Copyright (c) 2013 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.security.wsutil.client.authn;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Collection;
import java.util.Iterator;

import org.apache.commons.io.FileUtils;
import org.apache.log4j.Logger;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import eu.unicore.util.Log;
import eu.unicore.util.httpclient.ClientSecuritySession;
import eu.unicore.util.httpclient.SessionIDProvider;

/**
 * Responsible for Security sessions management: mostly loading from files and storing.
 * You can easily configure this class to have NOP implementation - simply disable sessions in constructor.
 * <p>
 * Concurrency note: this class can be used only in single thread mode. Using it concurrently can result in
 *  corrupted file.
 * @author K. Benedyczak
 */
public class JsonSecuritySessionPersistence implements SecuritySessionPersistence
{
	private static final Logger logger = Log.getLogger(Log.SECURITY, JsonSecuritySessionPersistence.class);
	private static final ObjectMapper mapper = new ObjectMapper();
	
	private boolean sessionsEnabled;
	private File sessionIDFile;
	
	public JsonSecuritySessionPersistence(boolean sessionsEnabled, String sessionsFile)
	{
		this.sessionsEnabled = sessionsEnabled;
		this.sessionIDFile = null;
		if (sessionsFile != null && sessionsEnabled)
		{
			this.sessionIDFile = new File(sessionsFile);
			FilePermHelper.set0600(this.sessionIDFile);			
		}
	}

	@Override
	public void storeSessionIDs(SessionIDProvider sessionProvider) throws IOException {
		if (!sessionsEnabled || sessionProvider == null)
			return;
		
		Collection<ClientSecuritySession> sessions = sessionProvider.getAllSessions();
		ObjectNode sessionsJson = mapper.createObjectNode();
		
		for(ClientSecuritySession entry: sessions){
			String serverID=entry.getScope();
			ObjectNode info = mapper.createObjectNode();
			info.put("sessionID", entry.getSessionId());
			info.put("hash", entry.getSessionHash());
			info.put("expiry", entry.getExpiryTS());
			sessionsJson.put(serverID,info);
		}
		if (sessions.size()>0) {
			if (sessionIDFile != null) {
				FileWriter writer=new FileWriter(sessionIDFile);
				mapper.writeValue(writer, sessionsJson);
				writer.close();
				logger.debug("Stored <"+sessions.size()+"> security session ID(s) to <"+
						sessionIDFile.getAbsolutePath());
			}
		}
	}

	@Override
	public void readSessionIDs(SessionIDProvider sessionProvider) throws IOException 
	{
		if (!sessionsEnabled || sessionProvider == null)
			return;
		
		if (sessionIDFile != null && sessionIDFile.exists()) {
			ObjectNode sessionsJSON = (ObjectNode) mapper.readTree(FileUtils.readFileToString(sessionIDFile));
			Iterator<String>serverIDs = sessionsJSON.fieldNames();
			while(serverIDs.hasNext()){
				String serverID=serverIDs.next();
				ObjectNode info=(ObjectNode) sessionsJSON.get(serverID);
				String hash=info.get("hash").asText();
				String sessionID=info.get("sessionID").asText();
				Long lifetime = info.get("expiry").asLong();
				if(lifetime!=null && lifetime<System.currentTimeMillis()){
					if(logger.isDebugEnabled())logger.debug("Session for "+serverID+" expired");
					continue;
				}
				if (logger.isDebugEnabled())
					logger.debug("Re-adding session for " + serverID + " id " + sessionID);
				ClientSecuritySession s = new ClientSecuritySession(sessionID, lifetime, 
						hash, serverID);
				sessionProvider.addSession(s);
			}
			
			logger.debug("Loaded <"+sessionProvider.getAllSessions().size() +
					"> security session ID(s) from <" + sessionIDFile.getAbsolutePath());
		}
	}
}
