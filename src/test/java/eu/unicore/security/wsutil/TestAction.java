package eu.unicore.security.wsutil;

import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Test;

public class TestAction extends AbstractTestBase
{
	@Test
	public void testAction() throws Exception {
		MockSecurityConfig config = new MockSecurityConfig(false, true, true);
		config.setMessageLogging(true);
		SimpleSecurityService s = makeSecuredProxy(config);

		String userRet = s.TestAction();
		assertNotNull(userRet);
		assertTrue(SimpleSecurityService.test_action.equals(userRet));
	}
	
}