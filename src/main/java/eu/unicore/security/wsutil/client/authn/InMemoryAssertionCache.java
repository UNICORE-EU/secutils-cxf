package eu.unicore.security.wsutil.client.authn;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.logging.log4j.Logger;

import xmlbeans.org.oasis.saml2.assertion.AssertionDocument;

import eu.unicore.samly2.assertion.AssertionParser;
import eu.unicore.security.wsutil.samlclient.AuthnResponseAssertions;
import eu.unicore.util.Log;

public class InMemoryAssertionCache implements AssertionsCache {

	protected final static Logger logger = Log.getLogger(Log.SECURITY, AssertionsCache.class);
	
	protected final Map<String, AuthnResponseAssertions>store = 
			new ConcurrentHashMap<String, AuthnResponseAssertions>();
	
	@Override
	public AuthnResponseAssertions get(String key) {
		return store.get(key);
	}

	@Override
	public void store(String key, AuthnResponseAssertions value) {
		if(logger.isDebugEnabled()){
			try{
				StringBuilder sb = new StringBuilder();
				String nl = System.getProperty("line.separator");
				   sb.append("Key: ").append(key).append(nl);
				for(AssertionParser p: value.getAuthNAssertions()){
					sb.append("Authn: ").append(p.getXMLBeanDoc()).append(nl);
				}
				for(AssertionParser p: value.getAttributeAssertions()){
					sb.append("Attrib: ").append(p.getXMLBeanDoc()).append(nl);
				}
				for(AssertionDocument p: value.getOtherAssertions()){
					sb.append("Other: ").append(p).append(nl);
				}
				logger.debug(sb.toString());
			}catch(Exception e){}
		}
		store.put(key, value);
	}

}
