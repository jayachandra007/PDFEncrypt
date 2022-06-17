package main.core.util;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class AESPDFUtil {
	private static final String FOLDER_PATH = "/home/jay/Documents/workspaces/pbcWS/HVE/src/main/resources/";
	private static final String FILE = "407-converted";
	private static final String EXT = ".pdf";

	private static final String ENCRYPTION_ALGORITHM = "AES";
	private static final int KEY_SIZE = 128; // 192 and 256 bits may not be available

	public static void main(String[] args) throws Exception {
		// Common stuff to encrypt/decrypt
		KeyGenerator kgen = KeyGenerator.getInstance(ENCRYPTION_ALGORITHM);
		SecureRandom secRandom = new SecureRandom();		
		kgen.init(KEY_SIZE, secRandom);
		
		SecretKey skey = kgen.generateKey();
		byte[] secretKey = skey.getEncoded();
		
		StringBuffer sk = new StringBuffer();
		for (int i = 0; i < secretKey.length; i++) {
			sk.append(Integer.toHexString(0xFF & secretKey[i]));
		}
		System.out.println(sk);
		
		SecretKeySpec skeySpec = new SecretKeySpec(secretKey, ENCRYPTION_ALGORITHM);
		Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);

		// Load file to encrypt
		byte[] largeFileBytes = Files.readAllBytes(Paths.get(FOLDER_PATH + FILE + EXT));

		// Encrypt file
		cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
		byte[] largeFileEncBytes = cipher.doFinal(largeFileBytes);

		// Save encrypted file
		Files.write(Paths.get(FOLDER_PATH + FILE + "-encrypted" + EXT), largeFileEncBytes);

		// Load encrypted file
		byte[] largeFileEncBytesToCheck = Files.readAllBytes(Paths.get(FOLDER_PATH + FILE + "-encrypted" + EXT));

		// Decrypt file
		cipher.init(Cipher.DECRYPT_MODE, skeySpec);
		byte[] largeFileBytesToCheck = cipher.doFinal(largeFileEncBytesToCheck);

		// Save decrypted file
		Files.write(Paths.get(FOLDER_PATH + FILE + "-decrypted" + EXT), largeFileBytesToCheck);

		// Compare results
		if (Arrays.equals(largeFileBytes, largeFileBytesToCheck)) {
			System.out.println("OK  :-) ");
		} else {
			System.out.println("KO  :-( ");
		}
	}
}
