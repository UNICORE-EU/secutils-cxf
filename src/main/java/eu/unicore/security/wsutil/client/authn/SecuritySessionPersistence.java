/*
 * Copyright (c) 2013 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.security.wsutil.client.authn;

import java.io.IOException;

import eu.unicore.util.httpclient.SessionIDProvider;

/**
 * Implementations are responsible for Security sessions persistence. Typically security sessions should out-live 
 * short-living clients (e.g. command line). If such feature is not needed a no-op implementation can be used.
 * @author K. Benedyczak
 */
public interface SecuritySessionPersistence
{
	public void storeSessionIDs(SessionIDProvider sessionProvider) throws IOException;
	public void readSessionIDs(SessionIDProvider sessionProvider) throws IOException;
}
