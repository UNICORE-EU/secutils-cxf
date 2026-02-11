package eu.unicore.security.wsutil.client.authn;

import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import org.apache.logging.log4j.Logger;

import eu.unicore.util.Log;
import eu.unicore.util.configuration.ConfigurationException;
import eu.unicore.util.configuration.PropertiesHelper;
import eu.unicore.util.configuration.PropertyMD;

/**
 * Configuration of SAMLAuthN
 * @author K. Benedyczak
 */
public class SAMLAuthNProperties extends PropertiesHelper
{
	private static final Logger log = Log.getLogger(Log.CONFIGURATION, SAMLAuthNProperties.class);

	public static final String PREFIX = "unity.";

	public static final String ADDRESS = "address";
	public static final String USERNAME = "username";
	public static final String PASSWORD = "password";
	
	
	public static final Map<String, PropertyMD> META = new HashMap<>();
	static
	{
		META.put(ADDRESS, new PropertyMD().setMandatory().setDescription(
				"The Unity SAML authentication service address."));
		META.put(USERNAME, new PropertyMD().setDescription("Username used to log in. " +
				"If not specified then it is asked interactively."));
		META.put(PASSWORD, new PropertyMD().setSecret().setDescription("Password used to log in. It is suggested " +
				"not to use this option for security reasons. If not given in configuration, " +
				"it will be asked interactively."));
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
