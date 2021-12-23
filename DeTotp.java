import java.lang.reflect.UndeclaredThrowableException; //Cung cấp các lớp và giao diện để lấy thông tin phản chiếu về các lớp và đối tượng -> Ngoại lệ có thể tạo ra không được khai báo
import java.security.GeneralSecurityException; //Cung cấp các lớp và giao diện cho khung bảo mật.
import java.security.DrbgParameters.NextBytes;
// Lớp GeneralSecurityException là một lớp ngoại lệ bảo mật chung cung cấp an toàn kiểu cho tất cả các lớp ngoại lệ liên quan đến bảo mật mở rộng từ nó.
import java.text.DateFormat;//DateFormat là một lớp trừu tượng dành cho các lớp con định dạng ngày / giờ để định dạng và phân tích cú pháp ngày hoặc giờ theo cách độc lập với ngôn ngữ.
import java.text.SimpleDateFormat;//SimpleDateFormat là một lớp cụ thể để định dạng và phân tích cú pháp ngày tháng theo cách nhạy cảm với ngôn ngữ.
import java.util.Date;//Lớp Date đại diện cho một thời điểm cụ thể trong thời gian, với độ chính xác mili giây.
import javax.crypto.Mac;//Lớp này cung cấp chức năng của thuật toán "Mã xác thực thông báo" (MAC).
import javax.crypto.spec.SecretKeySpec;//Một khóa bí mật (đối xứng).
import java.math.BigInteger;//BigInteger tương tự như kiểu dữ liệu nguyên thuỷ int, long nhưng cho phép lưu trữ giá trị kiểu số nguyên cực lớn, lớn hơn rất nhiều so với giá trị cực đại của int và long cho phép.
import java.util.TimeZone;//TimeZone thể hiện sự chênh lệch múi giờ và cũng tính toán mức tiết kiệm ánh sáng ban ngày.
import java.time.LocalDate;
import java.time.LocalTime;
import java.time.LocalDateTime;
import java.time.Month;
import java.util.Scanner;
// Thuận toán TOTP

public class DeTotp {

        private DeTotp() {
        }

        /**
         * Phương pháp này sử dụng JCE để cung cấp mã hóa.
         * HMAC tính toán Mã xác thực tin nhắn băm với thuật toán băm mã hóa như một
         * tham số.
         *
         * @param crypto:   mã hóa (HmacSHA1, HmacSHA256,
         *                  HmacSHA512)
         * @param keyBytes: byte để sử dụng cho khóa HMAC
         * @param text:     tin nhắn hoặc văn bản cần được xác thực
         */
        private static byte[] hmac_sha(String crypto, byte[] keyBytes,
                        byte[] text) {
                try {
                        Mac hmac; // Tạo biến xác thực thông báo
                        hmac = Mac.getInstance(crypto); // Trả về một đối tượng Mac thực hiện thuật toán MAC đã chỉ
                                                        // định.
                        SecretKeySpec macKey = new SecretKeySpec(keyBytes, "RAW");// Trả về một secret ky Mac thực hiện
                                                                                  // thuật toán MAC đã chỉ định.
                        // javax.crypto.spec.SecretKeySpec@2442
                        hmac.init(macKey);// Khởi tạo đối tượng Mac này bằng khóa đã cho.
                        /**
                         * do `update(buffer)`
                         * tính toán kết quả mật mã
                         * đặt lại phiên bản HmacSHA
                         * trả về kết quả mật mã
                         */

                        return hmac.doFinal(text);
                } catch (GeneralSecurityException gse) {
                        throw new UndeclaredThrowableException(gse);
                }
        }

        /**
         * Phương thức này chuyển đổi một chuỗi HEX thành Byte []**
         * 
         * @param hex: chuỗi HEX**@return:
         *             một mảng byte
         */

        private static byte[] covertHexToByte(String hex) {
                // Thêm một byte để có được chuyển đổi phù hợp
                // Các giá trị bắt đầu bằng "0" có thể được chuyển đổi
                byte[] bArray = new BigInteger("10" + hex, 16).toByteArray();
                // Trả về một mảng byte chứa biểu diễn bổ sung hai phần của BigInteger này. Mảng
                // byte sẽ theo thứ tự byte lớn-endian: byte quan trọng nhất nằm trong phần tử
                // thứ 0. Mảng sẽ chứa số byte tối thiểu cần thiết để đại diện cho BigInteger
                // này, bao gồm ít nhất một bit dấu, là (ceil ((this.bitLength () + 1) / 8)).
                // (Biểu diễn này tương thích với hàm tạo (byte []).)
                //

                // Sao chép tất cả các byte THỰC, không phải byte đầu tiên
                byte[] ret = new byte[bArray.length - 1];
                for (int i = 0; i < ret.length; i++)
                        ret[i] = bArray[i + 1];
                return ret;
        }

        private static final int[] DIGITS_POWER
        // 0 1 2 3 4 5 6 7 8
                        = { 1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000 };

        /**
         * Phương pháp này tạo ra giá trị TOTP cho giá trị đã cho
         * tập hợp các tham số.
         *
         * Khóa @param: bí mật được chia sẻ, được mã hóa HEX
         * 
         * @param time:         giá trị phản ánh thời gian
         * @param returnDigits: số chữ số cần trả về
         *
         * @return: một Chuỗi số trong cơ số 10 bao gồm
         *          {@link truncationDigits} chữ số
         */

        public static String generateTOTP(String key,
                        String time,
                        String returnDigits) {
                return generateTOTP(key, time, returnDigits, "HmacSHA1");
        }

        /**
         * Phương pháp này tạo ra giá trị TOTP cho giá trị đã cho
         * tập hợp các tham số.
         *
         * Khóa @param: bí mật được chia sẻ, được mã hóa HEX
         * 
         * @param time:         giá trị phản ánh thời gian
         * @param returnDigits: số chữ số cần trả về
         *
         * @return: một Chuỗi số trong cơ số 10 bao gồm
         *          {@link truncationDigits} chữ số
         */

        public static String generateTOTP256(String key,
                        String time,
                        String returnDigits) {
                return generateTOTP(key, time, returnDigits, "HmacSHA256");
        }

        /**
         * Phương pháp này tạo ra giá trị TOTP cho giá trị đã cho
         * tập hợp các tham số.
         *
         * Khóa @param: bí mật được chia sẻ, được mã hóa HEX
         * 
         * @param time:         giá trị phản ánh thời gian
         * @param returnDigits: số chữ số cần trả về
         *
         * @return: một Chuỗi số trong cơ số 10 bao gồm
         *          {@link truncationDigits} chữ số
         */

        public static String generateTOTP512(String key,
                        String time,
                        String returnDigits) {
                // key: [B@ed17bee
                // time: 12
                // 785503963
                return generateTOTP(key, time, returnDigits, "HmacSHA512");
        }

        /**
         * Phương pháp này tạo ra giá trị TOTP cho giá trị đã cho
         * tập hợp các tham số.
         *
         * Khóa @param: bí mật được chia sẻ, được mã hóa HEX
         * 
         * @param time:         giá trị phản ánh thời gian
         * @param returnDigits: số chữ số cần trả về
         * @param crypto:       chức năng mã hóa để sử dụng
         *
         * @return: một Chuỗi số trong cơ số 10 bao gồm
         *          {@link truncationDigits} chữ số
         */

        public static String generateTOTP(String key,
                        String time,
                        String returnDigits,
                        String crypto) {
                int codeDigits = Integer.decode(returnDigits).intValue();// chữ số mã | chuển từ string sang int
                String result = null;

                // Sử dụng bộ đếm
                // 8 byte đầu tiên dành cho movingFactor
                // Tuân theo RFC 4226 cơ sở (HOTP)
                while (time.length() < 16)
                        time = "0" + time;

                // Lấy HEX trong một Byte []
                byte[] msg = covertHexToByte(time);
                byte[] k = covertHexToByte(key);
                byte[] hash = hmac_sha(crypto, k, msg);

                // đặt các byte đã chọn vào kết quả int(1 byte cuối)
                /**
                 * 
                 * Tại sao & 0xff được áp dụng cho một biến byte trong việc triển khai tham
                 * chiếu của OTP dựa trên thời gian (TOTP, RFC 6238)?
                 * 
                 * Lí do: để đặt về số không dấu
                 * https://stackoverflow.com/questions/11380062/what-does-value-0xff-do-in-java
                 * https://stackoverflow.com/questions/48467832/why-is-0xff-applied-to-a-byte-variable
                 * 
                 */

                // Toán tử AND
                // Trả về giá trị là 1 nếu các toán hạng là 1 và 0 trong các trường hợp khác
                int offset = hash[hash.length - 1] & 0xf;

                int binary = ((hash[offset] & 0x7f) << 24) | // 0x7f được sử dụng trên byte cao được sử dụng thay vì
                                                             // 0xff để che dấu bit ngoài cùng bên trái (hoặc quan trọng
                                                             // nhất), là bit dấu, để đảm bảo kết quả cuối cùng không
                                                             // âm.
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

                String steps = "0";
                DateFormat df = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
                df.setTimeZone(TimeZone.getTimeZone("UTC"));
                try {

                        long T = (testTime - T0) / X;
                        steps = Long.toHexString(T).toUpperCase();
                        while (steps.length() < 16)
                                steps = "0" + steps;

                        System.out.println(generateTOTP(seed64, steps, "8", "HmacSHA512"));

                } catch (final Exception e) {
                        System.out.println("Error : " + e);
                }
        }
}
