using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographicTechnique<string, string>
    {
        /// <summary>
        /// The most common diagrams in english (sorted): TH, HE, AN, IN, ER, ON, RE, ED, ND, HA, AT, EN, ES, OF, NT, EA, TI, TO, IO, LE, IS, OU, AR, AS, DE, RT, VE
        /// </summary>
        /// <param name="plainText"></param>
        /// <param name="cipherText"></param>
        /// <returns></returns>
        public string Analyse(string plainText)
        {
            throw new NotImplementedException();
        }

        public string Analyse(string plainText, string cipherText)
        {
            throw new NotSupportedException();
        }
        public static string Duplicate(string key)
        {
            string resultString = string.Empty;
            for (int i = 0; i < key.Length; i++)
            {
                if (!resultString.Contains(key[i]))
                {
                    resultString += key[i];
                }
            }
            return resultString;

        }

        public static string Fillstring(string resultString)
        {

            resultString = Duplicate(resultString);
            string charsi = "abcdefghiklmnopqrstuvwxyz";
            for (int j = 0; j < charsi.Length; j++)
            {
                if (!resultString.Contains(charsi[j]))
                {
                    resultString += charsi[j];

                }

            }

            return resultString;
        }
        public static char[,] fillarr(string resultstring)
        {
            char[,] arr = new char[5, 5];
            resultstring = Fillstring(resultstring);
            int couter = 0;
            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    arr[i, j] = resultstring[couter];
                    couter++;

                    Console.Write(arr[i, j]);
                }
                Console.WriteLine();
            }

            return arr;
        }
        public static string removeX(string pt)
        {
            int y = 0;
            string new_pt = "";
            y = pt.Length;


            for (int i = 0; i < y - 1; i++)
            {
                if (!(pt[i] == 'x' && pt[i - 1] == pt[i + 1] && i % 2 != 0))
                {
                    new_pt += pt[i];
                }

            }
            if (pt[pt.Length - 1] != 'x')
            {
                new_pt += pt[pt.Length - 1];
            }
            return new_pt;
        }
        public static int[] getPositionn(char[,] arr_key, char first, char second)
        {
            int[] positions = new int[4];
            for (int i = 0; i < 4; i++)
            {
                positions[i] = 0;
            }
            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    if (arr_key[i, j] == first)
                    {
                        positions[0] = i; positions[1] = j;
                    }
                    if (arr_key[i, j] == second)
                    {
                        positions[2] = i; positions[3] = j;
                    }
                }
            }
            return positions;
        }
        public static string Playfair(string key, string cypher)
        {
            int count = 0;
            char[,] arr = new char[5, 5];
            arr = fillarr(key);
            string newcypher = cypher;
            int len = cypher.Length;
            string pt = "";
            int index1 = 0, index2 = 0;
            int index3 = 0, index4 = 0;

            int[] positions = new int[4];
            char[,] arr_key = new char[5, 5];

            string ret = "";

            arr_key = fillarr(key);



            for (int i = 0; i < cypher.Length; i += 2)
            {
                char decrpyt_char1;
                char decrypt_char2;
                positions = getPositionn(arr_key, cypher[i], cypher[i + 1]);
                if (positions[0] == positions[2])
                {
                    int col1 = (positions[1] - 1) % 5;
                    int col2 = (positions[3] - 1) % 5;
                    if (col1 < 0) col1 += 5;
                    if (col2 < 0) col2 += 5;
                    decrpyt_char1 = arr_key[positions[0], col1];
                    decrypt_char2 = arr_key[positions[2], col2];

                    //same row
                }
                else if (positions[1] == positions[3])
                {
                    int row1 = (positions[0] - 1) % 5;
                    int row2 = (positions[2] - 1) % 5;
                    if (row1 < 0) row1 += 5;
                    if (row2 < 0) row2 += 5;
                    decrpyt_char1 = arr_key[row1, positions[1]];
                    decrypt_char2 = arr_key[row2, positions[3]];
                    //same column
                }
                else
                {
                    decrpyt_char1 = arr_key[(positions[0]), (positions[3])];
                    decrypt_char2 = arr_key[(positions[2]), (positions[1])];
                    //diagonal
                }


                ret += decrpyt_char1;
                ret += decrypt_char2;

            }
            //removing unnessessery X
            string new_pt = removeX(ret);

            return new_pt;
        }

        public string Decrypt(string cipherText, string key)
        {
            return Playfair(key, cipherText.ToLower());
        }
        public struct Matrix
        {
            public Dictionary<char, Tuple<int, int>> KM;
            public List<List<char>> OM;
        }
        public HashSet<char> resultKey(string key)
        {
            string alphabet = "abcdefghiklmnopqrstuvwxyz"; //all alphabit without j
            HashSet<char> key1 = new HashSet<char>();
            int keyLength = key.Length;
            for (int i = 0; i < keyLength; i++)
            {
                if (key[i] == 'j')
                {
                    key1.Add('i');
                }
                else
                {
                    key1.Add(key[i]);
                }
            }

            for (int i = 0; i < 25; i++)
            {
                key1.Add(alphabet[i]);
            }

            return key1;

        }

        public Matrix func1(HashSet<char> Mkey)
        {
            Dictionary<char, Tuple<int, int>> AMatrix = new Dictionary<char, Tuple<int, int>>();
            List<List<char>> OMatrix = new List<List<char>>();
            int counter = 0;
            for (int i = 0; i < 5; i++)
            {
                List<char> tmp = new List<char>();
                for (int j = 0; j < 5; j++)
                {
                    if (counter < 25)
                    {
                        AMatrix.Add(Mkey.ElementAt(counter), new Tuple<int, int>(i, j));
                        tmp.Add(Mkey.ElementAt(counter));
                        counter++;
                    }
                }

                OMatrix.Add(tmp);
            }

            Matrix matrix_1 = new Matrix();
            matrix_1.KM = AMatrix;
            matrix_1.OM = OMatrix;

            return matrix_1;
        }

        public string Encrypt(string plainText, string key)
        {
            string CT = "";

            Matrix KOkey = func1(resultKey(key));
            for (int i = 0; i < plainText.Length - 1; i += 2)
            {
                if (plainText[i] == plainText[i + 1])
                {
                    plainText = plainText.Substring(0, i + 1) + 'x' + plainText.Substring(i + 1);
                }

            }
            if (plainText.Length % 2 == 1) plainText += 'x';
            int PTLength = plainText.Length;
            for (int i = 0; i < PTLength; i += 2)
            {
                char c1 = plainText[i], c2 = plainText[i + 1];
                //Both at same column
                if (KOkey.KM[c1].Item2 == KOkey.KM[c2].Item2)
                {
                    CT += KOkey.OM[(KOkey.KM[c1].Item1 + 1) % 5][KOkey.KM[c1].Item2];
                    CT += KOkey.OM[(KOkey.KM[c2].Item1 + 1) % 5][KOkey.KM[c2].Item2];
                }
                // Both at same row
                else if (KOkey.KM[c1].Item1 == KOkey.KM[c2].Item1)
                {
                    CT += KOkey.OM[KOkey.KM[c1].Item1][(KOkey.KM[c1].Item2 + 1) % 5];
                    CT += KOkey.OM[KOkey.KM[c2].Item1][(KOkey.KM[c2].Item2 + 1) % 5];
                }
                else
                {//Diagonal
                    CT += KOkey.OM[KOkey.KM[c1].Item1][KOkey.KM[c2].Item2];
                    CT += KOkey.OM[KOkey.KM[c2].Item1][KOkey.KM[c1].Item2];
                }
            }


            Console.WriteLine(CT.ToUpper());
            Console.WriteLine("\n\n");
            return CT.ToUpper();
        }


    }
}