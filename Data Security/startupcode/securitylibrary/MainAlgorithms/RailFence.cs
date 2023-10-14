using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            int key = 0;
            plainText = plainText.ToUpper();
            cipherText = cipherText.ToUpper();
            int flag = 0;
            for (int i = 1; i < plainText.Length; i++)
            {
                string ct = Encrypt(plainText, i);
                for (int j = 0; j < cipherText.Length; j++)
                {
                    if (ct[j] == cipherText[j])
                    {
                        flag = 1;
                    }
                    else
                    {
                        flag = 0;
                        break;
                    }

                }
                if (flag == 1)
                {
                    key = i;
                    break;
                }

            }

            return key;
        }

        public string Decrypt(string cipherText, int key)
        {
            string pt = "";
            int col = 0;
            int cont = 0;
            if (cipherText.Length % key != 0)
            {
                col = (cipherText.Length / key) + 1;
            }
            else
            {
                col = (cipherText.Length / key);
            }
            char[,] arr = new char[key, col];
            for (int i = 0; i < key; i++)
            {
                for (int j = 0; j < col; j++)
                {
                    if (cont >= cipherText.Length)
                    {
                        break;
                    }
                    arr[i, j] = cipherText[cont];
                    cont++;
                }
            }
            for (int i = 0; i < col; i++)
            {
                for (int j = 0; j < key; j++)
                {

                    pt += arr[j, i];
                }
            }
            return pt;
        }

        public string Encrypt(string plainText, int key)
        {
            string ct = "";
            int col = 0;
            if (plainText.Length % key != 0)
            {
                col = (plainText.Length / key) + 1;
            }
            else
            {
                col = (plainText.Length / key);
            }

            char[,] arr = new char[key, col];
            int cont = 0;
            for (int i = 0; i < col; i++)
            {
                for (int j = 0; j < key; j++)
                {
                    if (cont >= plainText.Length)
                    {
                        break;
                    }
                    arr[j, i] = plainText[cont];
                    cont++;
                }
            }
            for (int i = 0; i < key; i++)
            {
                for (int j = 0; j < col; j++)
                {
                    ct += arr[i, j];
                }
            }
            ct = ct.Replace("\0", string.Empty);
            return ct;

        }
    }
}
