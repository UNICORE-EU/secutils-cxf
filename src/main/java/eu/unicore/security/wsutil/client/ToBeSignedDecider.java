/*
 * Copyright (c) 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on May 31, 2008
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.security.wsutil.client;

import java.util.Vector;

import org.apache.ws.security.WSEncryptionPart;
import org.w3c.dom.Document;

/**
 * Implementation decides which elements shall be signed.
 * @author K. Benedyczak
 */
public interface ToBeSignedDecider
{
	/**
	 * Returns list of parts required to be signed.
	 * @param docToSign
	 * @return
	 */
	public Vector<WSEncryptionPart> getElementsToBeSigned(Document docToSign);
}
