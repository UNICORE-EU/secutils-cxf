/*
 * Copyright (c) 2013 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.security.wsutil.samlclient;

import java.util.List;

import eu.unicore.samly2.assertion.AssertionParser;
import eu.unicore.samly2.assertion.AttributeAssertionParser;

import xmlbeans.org.oasis.saml2.assertion.AssertionDocument;

/**
 * Provides access to assertions returned by the Authn Request protocol.
 * It is possible to get the authentication assertions and other assertions (usually attribute assertions).
 * @author K. Benedyczak
 */
public class AuthnResponseAssertions
{
	protected List<AssertionParser> authNAssertions;
	protected List<AttributeAssertionParser> attributeAssertions;
	protected List<AssertionDocument> otherAssertions;
	
	public AuthnResponseAssertions(List<AssertionParser> authNAssertions,
			List<AttributeAssertionParser> attributeAssertions,
			List<AssertionDocument> otherAssertions)
	{
		super();
		this.authNAssertions = authNAssertions;
		this.attributeAssertions = attributeAssertions;
		this.otherAssertions = otherAssertions;
	}
	
	public List<AssertionParser> getAuthNAssertions()
	{
		return authNAssertions;
	}
	public List<AttributeAssertionParser> getAttributeAssertions()
	{
		return attributeAssertions;
	}
	public List<AssertionDocument> getOtherAssertions()
	{
		return otherAssertions;
	}
}
