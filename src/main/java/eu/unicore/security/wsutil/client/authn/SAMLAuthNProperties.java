/*
 * Copyright (c) 2013 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.security.wsutil.client.authn;

import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import org.apache.log4j.Logger;

import eu.unicore.util.Log;
import eu.unicore.util.configuration.ConfigurationException;
import eu.unicore.util.configuration.PropertiesHelper;
import eu.unicore.util.configuration.PropertyMD;

/**
 * Configuration of the {@link SAMLAuthN}
 * @author K. Benedyczak
 */
public class SAMLAuthNProperties extends PropertiesHelper
{
	private static final Logger log = Log.getLogger(Log.CONFIGURATION, SAMLAuthNProperties.class);

	public static final String PREFIX = "unity.";

	public static final String ADDRESS = "address";
	public static final String USERNAME = "username";
	public static final String PASSWORD = "password";
	public static final String FILE = "assertionsCacheFile";
	
	
	public static final Map<String, PropertyMD> META = new HashMap<String, PropertyMD>();
	static
	{
		META.put(ADDRESS, new PropertyMD().setMandatory().setDescription(
				"The Unity SAML authentication service address."));
		META.put(USERNAME, new PropertyMD().setDescription("Username used to log in. " +
				"If not specified then it is asked interactively."));
		META.put(PASSWORD, new PropertyMD().setSecret().setDescription("Password used to log in. It is suggested " +
				"not to use this option for security reasons. If not given in configuration, " +
				"it will be asked interactively."));
		META.put(FILE, new PropertyMD().setPath().setDescription("File used to save assertions " +
				"obtained from the service. If the file is not specified, then assertions are not saved locally" +
				" what effects in neccessity to re-authenticate before each operation."));
	}

	public SAMLAuthNProperties(String prefix, Properties properties) throws ConfigurationException
	{
		super(prefix, properties, META, log);
	}
	
	public SAMLAuthNProperties(Properties properties) throws ConfigurationException
	{
		super(PREFIX, properties, META, log);
	}
}
