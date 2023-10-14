using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        public static bool IsCharExist(char[] sentence, char letter)
        {
            foreach (char character in sentence)
            {
                if (character == letter)
                    return true;
            }
            return false;
        }
        public static bool IsBetweenBoundaries(char letter)
        {
            if (letter >= 'a' && letter <= 'z')
                return true;
            return false;
        }
        public  string Analyse(string plainText, string cipherText) {
            cipherText = cipherText.ToLower();
            Char[] key = { '-', '-', '-', '-', '-', '-', '-', '-', '-', '-', '-', '-', '-', '-', '-', '-', '-', '-', '-', '-', '-', '-', '-', '-', '-', '-' };
            for (int i = 0; i < plainText.Length; i++)
                key[plainText[i] - 'a'] = cipherText[i];
            for (int i = 0; i < key.Length; i++)
            {
                if (IsBetweenBoundaries(key[i]))
                    continue;
                else if (key[i] == '-')
                {
                    if (!IsCharExist(key, (char)(key[i - 1] + 1)))
                        key[i] = (char)(key[i - 1] + 1);
                }
            }
            for (int i = 0; i < key.Length; i++)
            {
                if (!IsBetweenBoundaries(key[i]) || key[i] == '-')
                {
                    for (int j = 0; j < 26; j++)
                    {
                        if (!IsCharExist(key, (char)('a' + j)))
                            key[i] = (char)(j + 'a');
                    }
                }
            }
            return new string(key);
        }

        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToLower();
            string plainText = "";
            foreach(char letter in cipherText)
                plainText += (char)(key.IndexOf(letter) + 97);
            return plainText;
        }

        public string Encrypt(string plainText, string key)
        {
           string cipherText = "";
            foreach (char letter in plainText)
                cipherText += key[letter-97];
           return cipherText.ToUpper();
            
        }

        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        public string AnalyseUsingCharFrequency(string cipher)
        {
            cipher = cipher.ToLower();
            Dictionary<char, double> EnglishFrequencies = new Dictionary<char, double>(){ { 'a', 8.04 },{ 'b', 1.54 },{ 'c', 3.06 }
                , {'d',3.99 },{'e', 12.51 },{'f', 2.30 },{'g' ,1.96 },{'h' ,5.49 }, {'i',7.26 }, {'j', 0.16 },{'k', 0.67 }, {'l',4.14 },{'m', 2.53 }
                , {'n',7.09 }, {'o',7.60 }, {'p',2.00 }, {'q',0.11}, {'r',6.12 } ,{'s',6.54}, {'t',9.25 }, {'u',2.71 }, {'v',0.99 },{'w', 1.92 }
                , {'x',0.19 }, {'y', 1.73 }, {'z',0.09 } };
            Dictionary<char, double> cipherFrequiences = new Dictionary<char, double>();
            Dictionary<char, char> cipherAndkey = new Dictionary<char, char>();
            int[] countsOfLetters = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
            for (int i = 0; i < cipher.Length; i++)
            {
                countsOfLetters[cipher[i] - 97] += 1;
            }
            for (int i = 0; i < countsOfLetters.Length; i++)
            {
                cipherFrequiences.Add((char)(i + 'a'), (countsOfLetters[i]));
            }
            var sortedEnglishFreq = EnglishFrequencies.ToList();
            var sortedCipherFreq = cipherFrequiences.ToList();
            sortedEnglishFreq.Sort((pair1, pair2) => pair1.Value.CompareTo(pair2.Value));
            sortedCipherFreq.Sort((pair1, pair2) => pair1.Value.CompareTo(pair2.Value));
            char[] key = new char[26];
            for (int i = 0; i < sortedCipherFreq.Count; i++)
            {
                key[sortedEnglishFreq[i].Key - 'a'] = sortedCipherFreq[i].Key;
            }
            return Decrypt(cipher, new string(key));
        }
    }
}
