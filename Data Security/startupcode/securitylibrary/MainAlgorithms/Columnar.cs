using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        public List<int> Analyse(string plainText, string cipherText)
        {
            {
                cipherText = cipherText.ToLower();
                plainText = plainText.ToLower();
                List<int> key = new List<int>();
                int row = 0;
                int coloms = 0;
                int mkan = 0;
                int i = 0;

                do
                {
                    if (cipherText[0] == plainText[i])
                    {
                        int k = i + 1;
                        while (k < cipherText.Length)
                        {
                            if (cipherText[1] == plainText[k])
                            {
                                int y = i + 2;
                                while (y < cipherText.Length)
                                {
                                    if (cipherText[2] == plainText[y])
                                    {
                                        int p = i + 3;
                                        while (p < cipherText.Length)
                                        {
                                            if (cipherText[3] == plainText[p])
                                            {

                                                if (k - i != y - k)
                                                {
                                                    break;
                                                }
                                                else
                                                {
                                                    coloms = y - k;
                                                    if (cipherText.Length % coloms > 0 || cipherText.Length % coloms < 0)
                                                    {

                                                        row = cipherText.Length / coloms;
                                                        row++;
                                                    }
                                                    else
                                                    {

                                                        row = cipherText.Length / coloms;
                                                        break;
                                                    }
                                                }
                                            }
                                            p++;
                                        }
                                    }
                                    y++;
                                }

                            }
                            k++;
                        }
                    }
                    i++;
                } while (i < cipherText.Length);
                // get the array of plain text that i will test on it 
                char[,] arrayplaintext = new char[row, coloms];
                int ii = 0;
                do
                { for (int j = 0; j < coloms; j++) if (mkan < plainText.Length) arrayplaintext[ii, j] = plainText[mkan++]; ii++; }
                while (ii < row);


                int iii = 0;
                int krows = 0;
                while (iii < coloms)
                {
                    for (int k = 0; k < cipherText.Length; k++)
                    {
                        if (arrayplaintext[0, iii] == cipherText[k])
                        {
                            if (arrayplaintext[1, iii] == cipherText[k + 1])
                            {
                                if (arrayplaintext[2, iii] == cipherText[k + 2])
                                {

                                    krows = k / row;
                                    if (k % row > 0 || k % row < 0)
                                    {
                                        krows++;
                                    }
                                    key.Add(krows + 1);
                                    break;
                                }
                            }
                        }
                    }
                    iii++;
                }

                return key;
            }
        }
         public string Decrypt(string cipherText, List<int> key)
        {
            int coloum = key.Count;
            int character = 0;
            int rownum = (int)Math.Ceiling(cipherText.Length / (float)coloum);
            int drb = rownum * coloum;
            string decr = "";
            char[,] arrs = new char[coloum, rownum];


            if (drb == cipherText.Length)
            {
                //bn2el fe arr 2d
                int y = 0;
                while (y != coloum)
                { for (int j = 0; j < rownum; j++) arrs[y, j] = cipherText[character++]; y++; }
                int x = 0;
                while (x != rownum)
                { for (int j = 0; j < coloum; j++) decr += arrs[key[j] - 1, x]; x++; }

            }

            return decr;

        }
      public string Encrypt(string plainText, List<int> key)
        {
            int coloum = key.Count;
            string enctext = "";
            string[] arr = new string[30];
            for (int i = 0; i < 30; i++) arr[i] = "";
            int charachter = 0;
            int j = 0;
            int ik = 0;
            while (ik < coloum)
            {
                charachter = ik;
                for (int k = charachter; k < plainText.Length; k++)
                {
                    if (charachter < plainText.Length)
                    {

                        arr[key[j] - 1] += plainText[charachter];
                        charachter += coloum;
                    }
                }
                j++;
                ik++;
            }
            for (int i = 0; i < coloum; i++) enctext = enctext + arr[i];
            return enctext;
        }
    }
}
