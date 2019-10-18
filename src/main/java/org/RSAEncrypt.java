package org;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Map;
import java.util.HashMap;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;

public class RSAEncrypt {

  public Map<Integer, String> keyMap = new HashMap<Integer, String>();

  /**
   * 随机生成密钥对
   */
  public void genKeyPair() throws NoSuchAlgorithmException {
    // KeyPairGenerator类用于生成公钥和私钥对，基于RSA算法生成对象
    KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
    // 初始化密钥对生成器，密钥大小为96-1024位
    keyPairGen.initialize(1024, new SecureRandom());
    // 生成一个密钥对，保存在keyPair中
    KeyPair keyPair = keyPairGen.generateKeyPair();
    // 得到私钥
    RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
    // 得到公钥
    RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();

    String publicKeyString = Base64.getEncoder().encodeToString(publicKey.getEncoded());
    // 得到私钥字符串
    String privateKeyString = Base64.getEncoder().encodeToString(privateKey.getEncoded());

    keyMap.put(0, publicKeyString);
    keyMap.put(1, privateKeyString);
  }

  /**
   * RSA公钥加密
   *
   * @param str 加密字符串
   * @param publicKey 公钥
   * @return 密文
   * @throws Exception 加密过程中的异常信息
   */
  public String encrypt(String str, String publicKey)
      throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException,
      BadPaddingException, InvalidKeyException, IllegalBlockSizeException {
    //base64编码的公钥
    byte[] decoded = Base64.getDecoder().decode(publicKey);
    RSAPublicKey pubKey = (RSAPublicKey) KeyFactory.getInstance("RSA")
        .generatePublic(new X509EncodedKeySpec(decoded));
    //RSA加密
    Cipher cipher = Cipher.getInstance("RSA");
    cipher.init(Cipher.ENCRYPT_MODE, pubKey);
    byte[] result = cipher.doFinal(str.getBytes());
    String outStr = Base64.getEncoder().encodeToString(result);
    return outStr;
  }

  /**
   * RSA私钥解密
   *
   * @param str 加密字符串
   * @param privateKey 私钥
   * @return 明文
   * @throws Exception 解密过程中的异常信息
   */
  public String decrypt(String str, String privateKey)
      throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException,
      BadPaddingException, InvalidKeyException, IllegalBlockSizeException {
    //base64编码的私钥
    byte[] input = Base64.getDecoder().decode(str.getBytes());
    byte[] decoded = Base64.getDecoder().decode(privateKey);
    RSAPrivateKey priKey = (RSAPrivateKey) KeyFactory.getInstance("RSA")
        .generatePrivate(new PKCS8EncodedKeySpec(decoded));
    //RSA解密
    Cipher cipher = Cipher.getInstance("RSA");
    cipher.init(Cipher.DECRYPT_MODE, priKey);
    byte[] result = cipher.doFinal(input);
    String outStr = new String(result);
    return outStr;
  }
}
