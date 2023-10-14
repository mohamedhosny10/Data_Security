using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class AutokeyVigenere : ICryptographicTechnique<string, string>
    {
        public static string get_key(string key, string plainText)
        {

            string final_key = "";
            int x = 0;
            for (int i = 0; i < plainText.Length; i++)
            {
                if (plainText[0] == key[i] && plainText[1] == key[i + 1] && plainText[2] == key[i + 2])
                {
                    x = i;

                }

            }
            final_key = key.Substring(0, x);


            return final_key;
        }

        public string Analyse(string plainText, string cipherText)
        {
            cipherText = cipherText.ToLower();
            plainText = plainText.ToLower();
            string matrix = "abcdefghijklmnopqrstuvwxyz";
            List<int> Key = new List<int>();


            for (int i = 0; i < cipherText.Length; i++)
                Key.Add(cipherText[i] - plainText[i]);
            String finalize = "";
            for (int i = 0; i < cipherText.Length; i++)
            {

                if (Key[i] < 0)
                {
                    Key[i] = Key[i] + 26;
                }

                Console.WriteLine(Key[i]);
            }
            for (int i = 0; i < cipherText.Length; i++)
            {
                finalize += matrix[(Key[i])];
            }


            string final = "";
            final = get_key(finalize, plainText);
            Console.WriteLine(final);
            return final;
        }



        public static string finalize(string cipherText, string key)
        {
            string matrix = "abcdefghijklmnopqrstuvwxyz";
            string finalize = "";
            int[] arr = new int[100];
            int[] arr2 = new int[100];
            int[] new_arr = new int[100];

            for (int i = 0; i < key.Length; i++)
            {
                arr[i] = (key[i] - 97);

            }

            for (int i = 0; i < cipherText.Length; i++)
            {
                arr2[i] = (cipherText[i] - 97);


            }

            for (int i = 0; i < key.Length; i++)
            {
                new_arr[i] = arr2[i] - arr[i];

            }

            for (int i = 0; i < key.Length; i++)
            {

                if (new_arr[i] < 0)
                {
                    new_arr[i] = new_arr[i] + 26;
                }


            }

            for (int i = 0; i < key.Length; i++)
            {

                finalize += matrix[(new_arr[i]) % 26];

            }

            return finalize;
        }


        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToLower();
            key = key.ToLower();
            string matrix = "abcdefghijklmnopqrstuvwxyz";

            string final = "";

            int[] arr = new int[100];
            int[] arr2 = new int[100];
            int[] new_arr = new int[100];
            string new_plain = "";

            new_plain = finalize(cipherText, key);
            key += new_plain;

            while (true)
            {
                string new_key = "";
                string new_cipher = "";

                int v = 0;
                int z = 0;
                int len = 0;
                if (cipherText.Length - key.Length > key.Length)
                {
                    z = key.Length + key.Length - new_plain.Length;
                    len = key.Length - new_plain.Length;

                }
                else if (cipherText.Length - key.Length < key.Length)
                {
                    int p = 0;
                    len = key.Length - new_plain.Length;
                    p = key.Length - len;
                    z = key.Length;
                    while (true)
                    {
                        if (z > cipherText.Length)
                        {

                            z--;
                            if ((z) == cipherText.Length)
                            {
                                break;
                            }

                        }
                        else
                        {
                            break;
                        }


                    }


                }

                for (int j = len; j < z; j++)
                {
                    new_cipher += cipherText[j];

                }

                new_key = finalize(new_cipher, new_plain);

                new_plain = new_key;

                key += new_key;
                if (key.Length > cipherText.Length)
                {
                    key = key.Substring(0, cipherText.Length);
                    break;
                }
                else if (key.Length == cipherText.Length)
                {
                    break;
                }




            }

            for (int i = 0; i < key.Length; i++)
            {
                arr[i] = (key[i] - 97);

            }

            for (int i = 0; i < key.Length; i++)
            {
                arr2[i] = (cipherText[i] - 97);


            }
            for (int i = 0; i < key.Length; i++)
            {
                new_arr[i] = arr2[i] - arr[i];

            }

            for (int i = 0; i < key.Length; i++)
            {
                if (new_arr[i] < 0)
                {
                    new_arr[i] = new_arr[i] + 26;
                }

            }
            for (int i = 0; i < key.Length; i++)
            {
                final += matrix[(new_arr[i]) % 26];

            }

            return final;
        }



        public string Encrypt(string plainText, string key)
        {
            string new_key = "";
            string matrix = "abcdefghijklmnopqrstuvwxyz";
            string final = "";
            int[] arr = new int[100];
            int[] arr2 = new int[100];
            for (int i = 0; i < key.Length; i++)
            {
                new_key += key[i];
            }

            for (int i = 0; i < (plainText.Length - key.Length); i++)
            {
                new_key += plainText[i];
            }

            for (int i = 0; i < new_key.Length; i++)
            {
                arr[i] = (new_key[i] - 97);

            }
            for (int i = 0; i < new_key.Length; i++)
            {
                arr2[i] = (plainText[i] - 97);

            }
            for (int i = 0; i < new_key.Length; i++)
            {

                final += matrix[(arr[i] + arr2[i]) % 26];

            }

            return final.ToUpper();
        }
    }
}
