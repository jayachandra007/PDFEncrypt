package main.core.test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import main.core.util.AESCrypto;

public class AESCryptoTest {
	private static final String FOLDER_PATH = "/home/jay/Documents/workspaces/pbcWS/HVE/src/main/resources/";
	private static final String FILE = "docs.pdf";
	private static final String FILE_ENC = "docs-enc.pdf";
	private static final String EXT = ".pdf";

	public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException,
			IllegalBlockSizeException, BadPaddingException, IOException, InvalidAlgorithmParameterException {
		AESCrypto aesCrypto = new AESCrypto();
		SecretKey secretKey = aesCrypto.generateAESKey();
		byte[] encBytes = aesCrypto.AESEncyprtFile(FOLDER_PATH, FILE, secretKey);
		byte[] decBytes = aesCrypto.AESDecyprtFile(FOLDER_PATH, FILE_ENC, secretKey);
		byte[] fileContentsInBytes = Files.readAllBytes(Paths.get(FOLDER_PATH + FILE));
		if (Arrays.equals(fileContentsInBytes, decBytes)) {
			System.out.println("OK  :-) ");
		} else {
			System.out.println("KO  :-( ");
		}
	}

}
