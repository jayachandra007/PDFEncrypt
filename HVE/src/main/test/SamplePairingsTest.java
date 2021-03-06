package main.test;

import static org.junit.Assert.assertEquals;

import java.security.SecureRandom;
import java.util.Random;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

import it.unisa.dia.gas.crypto.fe.PredicateOnlyEncryptionScheme;
import it.unisa.dia.gas.crypto.jpbc.fe.hve.ip08.engines.HVEIP08PredicateOnlyEngine;
import it.unisa.dia.gas.crypto.jpbc.fe.hve.ip08.generators.HVEIP08KeyPairGenerator;
import it.unisa.dia.gas.crypto.jpbc.fe.hve.ip08.generators.HVEIP08ParametersGenerator;
import it.unisa.dia.gas.crypto.jpbc.fe.hve.ip08.generators.HVEIP08PredicateOnlySecretKeyGenerator;
import it.unisa.dia.gas.crypto.jpbc.fe.hve.ip08.params.HVEIP08EncryptionParameters;
import it.unisa.dia.gas.crypto.jpbc.fe.hve.ip08.params.HVEIP08KeyGenerationParameters;
import it.unisa.dia.gas.crypto.jpbc.fe.hve.ip08.params.HVEIP08MasterSecretKeyParameters;
import it.unisa.dia.gas.crypto.jpbc.fe.hve.ip08.params.HVEIP08Parameters;
import it.unisa.dia.gas.crypto.jpbc.fe.hve.ip08.params.HVEIP08PublicKeyParameters;
import it.unisa.dia.gas.crypto.jpbc.fe.hve.ip08.params.HVEIP08SecretKeyGenerationParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

public class SamplePairingsTest {

	public SamplePairingsTest() {
	}

	protected AsymmetricCipherKeyPair setup(int n) {
		HVEIP08KeyPairGenerator generator = new HVEIP08KeyPairGenerator();
		generator.init(new HVEIP08KeyGenerationParameters(new SecureRandom(), genBinaryParam(n)));

		return generator.generateKeyPair();
	}

	protected CipherParameters keyGen(CipherParameters privateKey, int... pattern) {
		HVEIP08PredicateOnlySecretKeyGenerator generator = new HVEIP08PredicateOnlySecretKeyGenerator();
		generator
				.init(new HVEIP08SecretKeyGenerationParameters((HVEIP08MasterSecretKeyParameters) privateKey, pattern));
		return generator.generateKey();
	}

	protected byte[] enc(CipherParameters publicKey, int... attributes) {
		try {
			PredicateOnlyEncryptionScheme engine = new HVEIP08PredicateOnlyEngine();
			engine.init(true, new HVEIP08EncryptionParameters((HVEIP08PublicKeyParameters) publicKey, attributes));
			return engine.process();
		} catch (InvalidCipherTextException e) {
			throw new RuntimeException(e);
		}
	}

	protected boolean evaluate(CipherParameters searchKey, byte[] ct) {
		try {
			PredicateOnlyEncryptionScheme engine = new HVEIP08PredicateOnlyEngine();
			engine.init(false, searchKey);

			return engine.evaluate(ct);
		} catch (InvalidCipherTextException e) {
			throw new RuntimeException(e);
		}
	}

	protected HVEIP08Parameters genBinaryParam(int n) {
		HVEIP08ParametersGenerator generator = new HVEIP08ParametersGenerator();
		generator.init(n, PairingFactory.getPairingParameters("params/curves/a.properties"));

		return generator.generateParameters();
	}

	protected int[][] createMatchingVectors(int n) {
		int[][] result = new int[2][n];
		Random random = new Random();

		for (int i = 0; i < n; i++) {
			if (i != 0 && i != 1 && random.nextBoolean()) {
				// it's a star
				result[0][i] = -1;
				result[1][i] = random.nextInt(2);
			} else {
				result[0][i] = random.nextInt(2);
				result[1][i] = result[0][i];
			}
		}
		return result;
	}

	protected int[][] createNonMatchingVectors(int n) {
		int[][] result = new int[2][n];
		Random random = new Random();
		for (int i = 0; i < n; i++) {
			if (i != 0 && i != 1 && random.nextBoolean()) {
				// it's a star
				result[0][i] = -1;
				result[1][i] = random.nextInt(2);
			} else {
				result[0][i] = random.nextInt(2);
				result[1][i] = 1 - result[0][i];
			}
		}
		return result;
	}

	public static void main(String[] args) {
		SamplePairingsTest hveip08 = new SamplePairingsTest();
		long start, end;

		int n = 5;
		AsymmetricCipherKeyPair keyPair = hveip08.setup(n);

		int[][] vectors = hveip08.createMatchingVectors(n);
		for(int []v : vectors) {
			for(int e : v) {
				System.out.print(e);
			}
			System.out.println();
		}
		// vector[0] -> 
		// vector[1] -> 
		start = System.nanoTime();
		assertEquals(true, hveip08.evaluate(hveip08.keyGen(keyPair.getPrivate(), vectors[0]),
				hveip08.enc(keyPair.getPublic(), vectors[1])));
		end = System.nanoTime();
		System.out.println(end - start);

		start = System.nanoTime();
		vectors = hveip08.createNonMatchingVectors(n);
		for(int []v : vectors) {
			for(int e : v) {
				System.out.print(e);
			}
			System.out.println();
		}
		
		assertEquals(false, hveip08.evaluate(hveip08.keyGen(keyPair.getPrivate(), vectors[0]),
				hveip08.enc(keyPair.getPublic(), vectors[1])));
		end = System.nanoTime();
		System.out.println(end - start);
	}

}
