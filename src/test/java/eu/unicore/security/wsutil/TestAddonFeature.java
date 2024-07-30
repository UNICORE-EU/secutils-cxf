package eu.unicore.security.wsutil;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.apache.cxf.Bus;
import org.apache.cxf.endpoint.Client;
import org.apache.cxf.endpoint.Server;
import org.apache.cxf.feature.Feature;
import org.apache.cxf.interceptor.InterceptorProvider;
import org.junit.jupiter.api.Test;

import eu.unicore.security.wsutil.client.WSClientFactory;
import eu.unicore.util.httpclient.IClientConfiguration;


public class TestAddonFeature extends AbstractTestBase
{

	static boolean featureWasSetup=false;

	@Test
	public void testAddFeature()throws Exception
	{
		featureWasSetup=false;
		MockSecurityConfig sec = new MockSecurityConfig(false, false, false); 
		SimpleSecurityService s = makeProxy(sec);

		assertTrue(featureWasSetup);
		
		String userRet = s.TestIP();
		assertNotNull(userRet);

	}

	@Override
	protected WSClientFactory getWSClientFactory(IClientConfiguration sec) {
		return new WSClientFactory(sec){

			@Override
			protected void initFeatures() {
				super.initFeatures();
				System.out.println("INIT 2");
				Feature test=new Feature() {

					@Override
					public void initialize(InterceptorProvider interceptorProvider, Bus bus) {
						throw new IllegalStateException();
					}

					@Override
					public void initialize(Client client, Bus bus) {
						assertNotNull(client);
						TestAddonFeature.featureWasSetup=true;
					}

					@Override
					public void initialize(Server server, Bus bus) {
						throw new IllegalStateException();
					}

					@Override
					public void initialize(Bus bus) {
						throw new IllegalStateException();
					}
				};
				features.add(test);
			}
		};
	}



}