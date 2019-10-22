package org;


import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;

public class AESUtil {

  private static final String defaultCharset = "UTF-8";
  private static final String KEY_AES = "AES";

  /**
   * Encrypt data
   *
   * @param data conetent to be encrpyted
   * @param key key
   */
  public static String encrypt(String data, String key) {
    return doAES(data, key, Cipher.ENCRYPT_MODE);
  }

  /**
   * Decrypt data
   *
   * @param data content to be decrypted
   * @param key key
   */
  public static String decrypt(String data, String key) {
    return doAES(data, key, Cipher.DECRYPT_MODE);
  }

  /**
   * Encrypt and decrypt body
   *
   * @param data operation target
   * @param key key
   * @param mode operation mode
   */
  private static String doAES(String data, String key, int mode) {
    try {
      if (data == null || key == null) {
        return null;
      }

      boolean encrypt = mode == Cipher.ENCRYPT_MODE;
      byte[] content;

      if (encrypt) {
        content = data.getBytes(defaultCharset);
      } else {
        content = parseHexStr2Byte(data);
      }

      // Construct key generator and speicify AES
      KeyGenerator kgen = KeyGenerator.getInstance(KEY_AES);
      // window can below this method
      //kgen.init(128, new SecureRandom(key.getBytes()));
      SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
      secureRandom.setSeed(key.getBytes());
      kgen.init(128, secureRandom);

      // Generate origin symmetric key
      SecretKey secretKey = kgen.generateKey();
      byte[] enCodeFormat = secretKey.getEncoded();
      SecretKeySpec keySpec = new SecretKeySpec(enCodeFormat, KEY_AES);
      // Create cipher
      Cipher cipher = Cipher.getInstance(KEY_AES);
      cipher.init(mode, keySpec);
      byte[] result = cipher.doFinal(content);
      if (encrypt) {
        //Binary to hex
        return parseByte2HexStr(result);
      } else {
        // byte to string
        return new String(result, defaultCharset);
      }
    } catch (Exception e) {
      e.printStackTrace();
    }
    return null;
  }

  /**
   * Binary to hex format
   */
  public static String parseByte2HexStr(byte buf[]) {
    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < buf.length; i++) {
      String hex = Integer.toHexString(buf[i] & 0xFF);
      if (hex.length() == 1) {
        hex = '0' + hex;
      }
      sb.append(hex.toUpperCase());
    }
    return sb.toString();
  }

  /**
   * Hex to binary method
   */
  public static byte[] parseHexStr2Byte(String hexStr) {
    if (hexStr.length() < 1) {
      return null;
    }
    byte[] result = new byte[hexStr.length() / 2];
    for (int i = 0; i < hexStr.length() / 2; i++) {
      int high = Integer.parseInt(hexStr.substring(i * 2, i * 2 + 1), 16);
      int low = Integer.parseInt(hexStr.substring(i * 2 + 1, i * 2 + 2), 16);
      result[i] = (byte) (high * 16 + low);
    }
    return result;
  }
}
