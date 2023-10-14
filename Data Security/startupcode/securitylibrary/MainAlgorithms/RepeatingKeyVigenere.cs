using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            string key = string.Empty;
            string temp_key = string.Empty;
            plainText = plainText.ToUpper();
            cipherText = cipherText.ToUpper();

            for (int i = 0; i < cipherText.Length && i < plainText.Length; i++)
            {
                int k = (cipherText[i] - plainText[i] + 26) % 26;
                k += 'A';
                key += (char)(k);
            }

            temp_key = temp_key + key[0];
            for (int i = 1; i < key.Length; i++)
            {
                if (cipherText.Equals(Encrypt(plainText, temp_key)))
                {
                    return temp_key;
                }
                temp_key = temp_key + key[i];
            }
            return key;
        }

        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToUpper();
            key = key.ToUpper();

            String plainText = string.Empty;

            for (int i = 0; ; i++)
            {
                if (cipherText.Length == i)
                    i = 0;
                if (key.Length == cipherText.Length) break;
                key += (key[i]);
            }

            for (int i = 0; i < cipherText.Length && i < key.Length; i++)
            {
                int plain = (cipherText[i] - key[i] + 26) % 26;
                plain += 'A';
                plainText += (char)(plain);
            }

            return plainText;
        }



        public string Encrypt(string plainText, string key)
        {
            plainText = plainText.ToUpper();
            key = key.ToUpper();

            for (int i = 0; ; i++)
            {
                if (plainText.Length == i)
                    i = 0;
                if (key.Length == plainText.Length)
                    break;
                key += (key[i]);
            }

            String cipherText = string.Empty;

            for (int i = 0; i < plainText.Length; i++)
            {
                int cipher = (plainText[i] + key[i]) % 26;
                cipher += 'A';
                cipherText += (char)(cipher);
            }
            return cipherText;



        }
    }
}