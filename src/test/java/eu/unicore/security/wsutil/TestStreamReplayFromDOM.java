package eu.unicore.security.wsutil;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.FileInputStream;

import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.cxf.staxutils.StaxUtils;
import org.apache.cxf.staxutils.W3CDOMStreamReader;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;

import eu.unicore.security.dsig.StandaloneCanonizer;

/**
 * This tests whether a document read to DOM and then canonized is equal to this document
 * which is moved through STAX {@link W3CDOMStreamReader2} and then read by STAXUtils.
 * If this is OK, then we can be sure that signature verification of elements in the
 * request (other then the whole request: e.g. ETD or SAML assertions) will be OK.
 * <p>
 * XMLs for tests are taken from the XML c14n test suite. 
 * @author K. Benedyczak
 */
public class TestStreamReplayFromDOM 
{

	private final String PFX = "src/test/resources/merlin-xmldsig-eight/example-";

	@Test
	public void test() throws Exception
	{
		//TODO - the current, fixed implementation doesn't process XML
		//processing instructions correctly, so test number 1 won't go.
		for (int i=2; i<=7; i++)
		{
			testSingle(PFX+i+".xml");
			System.out.println("\n\n==============================\n");
		}
	}

	private void testSingle(String file) throws Exception
	{
		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(true);
		Document doc = dbf.newDocumentBuilder().parse(new FileInputStream(file), "");
		W3CDOMStreamReader replayStream = new W3CDOMStreamReader(doc.getDocumentElement());

		StandaloneCanonizer canon = new StandaloneCanonizer();
		String origShot = canon.fireCanon(doc, false);

		Document doc2 = StaxUtils.read(dbf.newDocumentBuilder(), 
			replayStream, false);

		String mangledShot = canon.fireCanon(doc2, false);

		System.out.println(origShot + "\n\n---------\n");

		System.out.println(mangledShot);
		assertEquals(origShot, mangledShot);
	}
}
