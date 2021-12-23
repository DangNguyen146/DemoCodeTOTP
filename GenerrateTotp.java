import java.lang.reflect.UndeclaredThrowableException;
import java.security.GeneralSecurityException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.util.TimeZone;
import java.util.Scanner;

public class GenerrateTotp {

        private GenerrateTotp() {
        }

        private static byte[] hmac_sha(String crypto, byte[] keyBytes,
                        byte[] text) {
                try {
                        Mac hmac;
                        hmac = Mac.getInstance(crypto);
                        SecretKeySpec macKey = new SecretKeySpec(keyBytes, "RAW");
                        hmac.init(macKey);
                        return hmac.doFinal(text);
                } catch (GeneralSecurityException gse) {
                        throw new UndeclaredThrowableException(gse);
                }
        }

        private static byte[] covertHexToByte(String hex) {
                byte[] bArray = new BigInteger("10" + hex, 16).toByteArray();
                byte[] ret = new byte[bArray.length - 1];
                for (int i = 0; i < ret.length; i++)
                        ret[i] = bArray[i + 1];
                return ret;
        }

        private static final int[] DIGITS_POWER = { 1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000 };

        public static String generateTOTP512(String key,
                        String time,
                        String returnDigits) {
                return generateTOTP(key, time, returnDigits, "HmacSHA512");
        }

        public static String generateTOTP(String key,
                        String time,
                        String returnDigits,
                        String crypto) {
                int codeDigits = Integer.decode(returnDigits).intValue();
                String result = null;
                while (time.length() < 16)
                        time = "0" + time;

                // Lấy HEX trong một Byte []
                byte[] msg = covertHexToByte(time);
                byte[] k = covertHexToByte(key);
                byte[] hash = hmac_sha(crypto, k, msg);
                int offset = hash[hash.length - 1] & 0xf;

                int binary = ((hash[offset] & 0x7f) << 24) |
                                ((hash[offset + 1] & 0xff) << 16) |
                                ((hash[offset + 2] & 0xff) << 8) |
                                (hash[offset + 3] & 0xff);
                int otp = binary % DIGITS_POWER[codeDigits];

                result = Integer.toString(otp);
                while (result.length() < codeDigits) {
                        result = "0" + result;
                }
                return result;
        }

        public static void main(String[] args) {
                String seed64 = "1468200114682001146814682001146820011468" +
                                "1468200114682001146814682001146820011468" +
                                "1468200114682001146814682001146820011468" +
                                "31323334";

                long T0 = 0;
                long X = 30;
                Date date = new Date();
                long testTime = date.getTime() / 5000;
                System.out.println(testTime);

                String steps = "0";
                DateFormat df = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
                df.setTimeZone(TimeZone.getTimeZone("UTC"));
                try {

                        long T = (testTime - T0) / X;
                        steps = Long.toHexString(T).toUpperCase();
                        while (steps.length() < 16)
                                steps = "0" + steps;
                        int category;
                        Scanner input = new Scanner(System.in);
                        System.out.println("Nhap lựa chọn: ");
                        category = input.nextInt();
                        input.nextLine();
                        switch (category) {
                                case 1: {
                                        System.out.println(generateTOTP(seed64, steps, "8", "HmacSHA512"));
                                        break;
                                }
                                case 2: {
                                        String code = null;
                                        System.out.print("Nhập code: ");
                                        code = input.nextLine();
                                        String test = generateTOTP(seed64, steps, "8", "HmacSHA512");

                                        if (code.equals(test))
                                                System.out.println(1);
                                        else
                                                System.out.println(0);
                                        break;
                                }
                        }

                } catch (final Exception e) {
                        System.out.println("Error : " + e);
                }
        }
}
