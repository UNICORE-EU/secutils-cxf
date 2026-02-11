package eu.unicore.security.wsutil.client.authn;

import java.io.File;

/**
 * Allows to set secure file permissions.
 * 
 * @author K. Benedyczak
 */
public class FilePermHelper
{
	public static void set0600(File file)
	{
		file.setReadable(false, false);
		file.setReadable(true, true);
		file.setWritable(false, false);
		file.setWritable(true, true);
		file.setExecutable(false, false);
	}
}
