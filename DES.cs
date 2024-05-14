using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class DES : CryptographicTechnique
    {
        public override string Decrypt(string cipherText, string key)
        {
            int[] IP = new int[] { 58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7 };
            int[,,] All_sbox = new int[,,] {
            { { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 },
              { 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 },
              { 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 },
              { 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 } },

            { { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 },
              { 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 },
              { 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 },
              { 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 } },

            { { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 },
              { 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 },
              { 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 },
              { 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 } },

            { { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 },
              { 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 },
              { 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 },
              { 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 } },

            { { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 },
              { 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 },
              { 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 },
              { 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 } },

            { { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 },
              { 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 },
              { 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 },
              { 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 } },

            { { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 },
              { 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 },
              { 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 },
              { 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 } },

            { { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 },
              { 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 },
              { 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 },
              { 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 } }
        };

            string converted_binary_key = ConvertToBinary(key.Substring(2));
            string binary_cipher_text = ConvertToBinary(cipherText.Substring(2));
            All_OperationsOnTheKey(converted_binary_key);
            string[] arr = ReversedArr(keys_in_binary);

            string res_plaintxt = "";
            for (int i = 0; i < 64; ++i)
            {
                res_plaintxt += binary_cipher_text[IP[i] - 1];
            }

            string lf_text = res_plaintxt.Substring(0, 32);
            string rt_text = res_plaintxt.Substring(32);

            for (int i = 0; i < 16; ++i)
            {
                string right_expanded_text = Right_text(rt_text);
                string xorResult = XOR(right_expanded_text, arr[i]);

                string final_res = "";
                for (int j = 0; j < 8; j++)
                {
                    int row = 2 * (xorResult[j * 6] - '0') + (xorResult[j * 6 + 5] - '0');
                    int col = 8 * (xorResult[j * 6 + 1] - '0') + 4 * (xorResult[j * 6 + 2] - '0') + 2 *
                        (xorResult[j * 6 + 3] - '0') + (xorResult[j * 6 + 4] - '0');
                    int m = All_sbox[j, row, col];
                    final_res += Convert.ToChar(m / 8 + '0');
                    m = m % 8;
                    final_res += Convert.ToChar(m / 4 + '0');
                    m = m % 4;
                    final_res += Convert.ToChar(m / 2 + '0');
                    m = m % 2;
                    final_res += Convert.ToChar(m + '0');
                }
                string new_final_res = "";
                new_final_res = PermutationAfterSbox(final_res);
                string left_xored = XOR(new_final_res, lf_text);
                lf_text = left_xored;

                string temp = "";
                if (i != 15)
                {
                    temp = lf_text;
                    lf_text = rt_text;
                    rt_text = temp;
                }
            }
            string main_plaintext = lf_text + rt_text;
            string laststep = initial_permintation(main_plaintext);
            laststep = convertToHex(laststep);
            return ("0x" + laststep);
        }

        public override string Encrypt(string plainText, string key)
        {
            int[,,] All_sbox = new int[,,] {
            { { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 },
              { 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 },
              { 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 },
              { 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 } },

            { { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 },
              { 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 },
              { 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 },
              { 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 } },

            { { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 },
              { 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 },
              { 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 },
              { 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 } },

            { { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 },
              { 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 },
              { 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 },
              { 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 } },

            { { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 },
              { 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 },
              { 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 },
              { 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 } },

            { { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 },
              { 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 },
              { 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 },
              { 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 } },

            { { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 },
              { 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 },
              { 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 },
              { 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 } },

            { { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 },
              { 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 },
              { 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 },
              { 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 } }
        };

            string converted_binary_key = ConvertToBinary(key.Substring(2));
            All_OperationsOnTheKey(converted_binary_key);
            string converted_binary_plaintext = ConvertToBinary(plainText.Substring(2));

            int[] IP = new int[] {58, 50, 42, 34, 26, 18, 10, 2,
                                                     60, 52, 44, 36, 28, 20, 12, 4,
                                                     62, 54, 46, 38, 30, 22, 14, 6,
                                                     64, 56, 48, 40, 32, 24, 16, 8,
                                                     57, 49, 41, 33, 25, 17, 9, 1,
                                                     59, 51, 43, 35, 27, 19, 11, 3,
                                                     61, 53, 45, 37, 29, 21, 13, 5,
                                                     63, 55, 47, 39, 31, 23, 15, 7 };
            string res_plaintxt = "";
            for (int i = 0; i < 64; ++i)
            {
                res_plaintxt += converted_binary_plaintext[IP[i] - 1];
            }

            string lf_text = res_plaintxt.Substring(0, 32);
            string rt_text = res_plaintxt.Substring(32);

            for (int i = 0; i < 16; ++i)
            {
                string right_expanded_text = Right_text(rt_text);
                string xorResult = XOR(right_expanded_text, keys_in_binary[i]);

                string final_res = "";
                for (int j = 0; j < 8; j++)
                {
                    int row = 2 * (xorResult[j * 6] - '0') + (xorResult[j * 6 + 5] - '0');
                    int col = 8 * (xorResult[j * 6 + 1] - '0') + 4 * (xorResult[j * 6 + 2] - '0') + 2 *
                        (xorResult[j * 6 + 3] - '0') + (xorResult[j * 6 + 4] - '0');
                    int m = All_sbox[j, row, col];
                    final_res += Convert.ToChar(m / 8 + '0');
                    m = m % 8;
                    final_res += Convert.ToChar(m / 4 + '0');
                    m = m % 4;
                    final_res += Convert.ToChar(m / 2 + '0');
                    m = m % 2;
                    final_res += Convert.ToChar(m + '0');
                }
                string new_final_res = "";
                new_final_res = PermutationAfterSbox(final_res);
                string left_xored = XOR(new_final_res, lf_text);
                lf_text = left_xored;

                string temp = "";
                if (i != 15)
                {
                    temp = lf_text;
                    lf_text = rt_text;
                    rt_text = temp;
                }
            }
            string main_plaintext = lf_text + rt_text;
            string laststep = initial_permintation(main_plaintext);
            laststep = convertToHex(laststep);
            return ("0x" + laststep);
        }

        static string[] keys_in_hex = new string[16];
        static string[] keys_in_binary = new string[16];
        static string[] reversed_Key = new string[16];

        public static string ConvertToBinary(string key)
        {
            string[] numbers = new string[] { "0000", "0001", "0010", "0011", "0100", "0101", "0110", "0111", "1000", "1001", "1010"
                , "1011", "1100", "1101", "1110", "1111" };
            string result = "";
            for (int i = 0; i < key.Length; ++i)
            {
                if (key[i].Equals('A')) result += numbers[10];
                else if (key[i].Equals('B')) result += numbers[11];
                else if (key[i].Equals('C')) result += numbers[12];
                else if (key[i].Equals('D')) result += numbers[13];
                else if (key[i].Equals('E')) result += numbers[14];
                else if (key[i].Equals('F')) result += numbers[15];
                else result += numbers[key[i] - '0'];
            }
            return result;
        }
        public static string initial_permintation(string s)
        {
            int[] IP_1 = new int[] { 40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25 };

            string laststep = "";
            for (int i = 0; i < 64; ++i)
            {
                laststep += s[IP_1[i] - 1];
            }
            return laststep;
        }
        public static string convertToHex(string send)
        {
            Dictionary<string, string> NumbersInBinary = new Dictionary<string, string>();
            NumbersInBinary["0000"] = "0";
            NumbersInBinary["0001"] = "1";
            NumbersInBinary["0010"] = "2";
            NumbersInBinary["0011"] = "3";
            NumbersInBinary["0100"] = "4";
            NumbersInBinary["0101"] = "5";
            NumbersInBinary["0110"] = "6";
            NumbersInBinary["0111"] = "7";
            NumbersInBinary["1000"] = "8";
            NumbersInBinary["1001"] = "9";
            NumbersInBinary["1010"] = "A";
            NumbersInBinary["1011"] = "B";
            NumbersInBinary["1100"] = "C";
            NumbersInBinary["1101"] = "D";
            NumbersInBinary["1110"] = "E";
            NumbersInBinary["1111"] = "F";

            string ResultHexa = "";
            for (int i = 0; i < send.Length; i += 4)
            {
                string index = send.Substring(i, 4);
                ResultHexa += NumbersInBinary[index];
            }
            return ResultHexa;
        }
        public static string XOR(string param1, string param2)
        {
            StringBuilder result = new StringBuilder(param1.Length);
            for (int i = 0; i < param1.Length; ++i)
            {
                if (param1[i].Equals(param2[i]))
                {
                    result.Append('0');
                }
                else
                {
                    result.Append('1');
                }
            }
            return result.ToString();
        }
        public static string Right_text(string send)
        {
            int[] EB = new int[] { 32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1 };

            StringBuilder new_s = new StringBuilder(48);
            for (int i = 0; i < 48; ++i)
            {
                new_s.Append(send[EB[i] - 1]);
            }
            return new_s.ToString();
        }

        public static string PermutationAfterSbox(string pa)
        {
            int[] P = new int[] {16, 7, 20, 21,
                                     29, 12, 28, 17,
                                     1, 15, 23, 26,
                                     5, 18, 31, 10,
                                     2, 8, 24, 14,
                                     32, 27, 3, 9,
                                     19, 13, 30, 6,
                                     22, 11, 4, 25};
            StringBuilder result = new StringBuilder();
            for (int i = 0; i < 32; ++i)
            {
                result.Append(pa[P[i] - 1]);
            }
            return result.ToString();
        }
        public static void All_OperationsOnTheKey(string key)
        {
            int[] PC_1 = new int[] {57, 49, 41, 33, 25, 17, 9,
                                             1, 58, 50, 42, 34, 26, 18,
                                             10, 2, 59, 51, 43, 35, 27,
                                             19, 11, 3, 60, 52, 44, 36,
                                             63, 55, 47, 39, 31, 23, 15,
                                             7, 62, 54, 46, 38, 30, 22,
                                             14, 6, 61, 53, 45, 37, 29,
                                             21, 13, 5, 28, 20, 12, 4};
            string result = "";
            for (int i = 0; i < PC_1.Length; ++i)
            {
                result += key[PC_1[i] - 1];
            }

            string lf = result.Substring(0, 28);
            string rt = result.Substring(28);

            int[] shifts = new int[] { 1, 1, 2, 2,
                                       2, 2, 2, 2,
                                       1, 2, 2, 2,
                                       2, 2, 2, 1};
            for (int i = 0; i < 16; ++i)
            {
                lf = left_Shift(shifts[i], lf);
                rt = left_Shift(shifts[i], rt);

                string combinekey = lf + rt;
                string new_round_key = last_permutation(combinekey);
                keys_in_binary[i] = new_round_key;
                keys_in_hex[i] = convertToHex(new_round_key);
            }
        }
        public static string left_Shift(int num_of_shifts, string snum)
        {
            StringBuilder new_snum = new StringBuilder(snum.Length);
            if (num_of_shifts == 1)
            {
                new_snum.Append(snum, 1, snum.Length - 1);
                new_snum.Append(snum[0]);
            }
            else
            {
                new_snum.Append(snum, 2, snum.Length - 2);
                new_snum.Append(snum[0]);
                new_snum.Append(snum[1]);
            }
            return new_snum.ToString();

        }

        public static string last_permutation(string key)
        {
            int[] key_permutation = new int[] {14, 17, 11, 24, 1, 5,
                                       3, 28, 15, 6, 21, 10,
                                       23, 19, 12, 4, 26, 8,
                                       16, 7, 27, 20, 13, 2,
                                       41, 52, 31, 37, 47, 55,
                                       30, 40, 51, 45, 33, 48,
                                       44, 49, 39, 56, 34, 53,
                                       46, 42, 50, 36, 29, 32};
            StringBuilder key_permutated = new StringBuilder(48);
            for (int i = 0; i < 48; ++i)
            {
                int index = key_permutation[i] - 1;
                key_permutated.Append(key[index]);
            }
            return key_permutated.ToString();
        }
        public static string[] ReversedArr(string[] key)
        {
            int b = 0;
            for (int i = 15; i >= 0; --i)
            {
                reversed_Key[b] = keys_in_binary[i];
                b++; ;
            }
            for (int i = 0; i < 16; ++i)
            {
                keys_in_binary[i] = reversed_Key[i];
            }
            return keys_in_binary;
        }
    }
}
