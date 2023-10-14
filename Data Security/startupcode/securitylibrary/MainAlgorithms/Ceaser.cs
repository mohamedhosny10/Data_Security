using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        public string Encrypt(string plainText, int key)
        {
            string cipherText = "";
            foreach (char letter in plainText)
            {
                cipherText += (char)(((letter) + key - 97) % 26 + 97);
            }
            return cipherText;
        }

        public string Decrypt(string cipherText, int key)
        {
            return Encrypt(cipherText.ToLower(), 26 - key);
        }
        int key;
        public int Analyse(string plainText, string cipherText)
        {
            return ((cipherText.ToLower()[0] - plainText[0])+ 26)%26;
        }
    }
}