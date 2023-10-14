using System;
using System.Collections.Generic;
using System.Drawing.Drawing2D;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Media;

namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    public class HillCipher : ICryptographicTechnique<string, string>, ICryptographicTechnique<List<int>, List<int>>
    {
        public static int getDetermentOfTwoD_matrix(int[,] arr)
        {
            return ((arr[0, 0] * arr[1, 1]) - (arr[0, 1] * arr[1, 0]));

        }
        public static int getDetermentOfThreeD_matrix(int[,] matrix)
        {
            int det = 0;
            for (int i = 0; i < 3; i++)
            {
                det = det + (matrix[0, i] * (matrix[1, (i + 1) % 3] * matrix[2, (i + 2) % 3] - matrix[1, (i + 2) % 3] * matrix[2, (i + 1) % 3]));
            }
            return det;
        }
        public static int getPositiveModulus(int number)
        {
            while (number < 0)
            {
                number += 26;
            }
            return number;
        }
        private static int CalculateB(int determinant)
        {
            int B;
            for (B = 1; ((B % 26) * (determinant % 26)) % 26 != 1; B++) ;
            return B;
        }
        private static int[,] getMatrixTranspose(int[,] matrix)
        {
            int sqrtMatrixSize = (int)Math.Sqrt(matrix.Length);
            int[,] transposedMatrix = new int[sqrtMatrixSize, sqrtMatrixSize];
            for (int i = 0; i < sqrtMatrixSize; i++)
            {
                for (int j = 0; j < sqrtMatrixSize; j++)
                {
                    transposedMatrix[i, j] = matrix[j, i];
                }

            }
            return transposedMatrix;
        }
        public static int[,] calculateMultiplicativeInverse(int[,] keyMatrix)
        {
            int sqrtKeySize = (int)Math.Sqrt(keyMatrix.Length);
            int[,] inverseMatrix = new int[sqrtKeySize, sqrtKeySize];
            int determinant = 0;
            if (Math.Sqrt(keyMatrix.Length) == 2)
                determinant = CalculateB(getPositiveModulus(getDetermentOfTwoD_matrix(keyMatrix)));
            else
                determinant = CalculateB(getPositiveModulus(getDetermentOfThreeD_matrix(keyMatrix)));
            if (sqrtKeySize > 2)
            {
                for (int i = 0; i < Math.Sqrt(keyMatrix.Length); i++)
                {
                    for (int j = 0; j < Math.Sqrt(keyMatrix.Length); j++)
                    {
                        inverseMatrix[i, j] = Math.Abs((((int)(determinant * (Math.Pow(-1, (i + j))) * getPositiveModulus(getMinorMatrix(keyMatrix)[i, j]))) % 26));
                    }
                }
            }
            else
            {
                for (int i = 0; i < Math.Sqrt(keyMatrix.Length); i++)
                {
                    for (int j = 0; j < Math.Sqrt(keyMatrix.Length); j++)
                    {
                        inverseMatrix[i, j] = (((int)(determinant * (Math.Pow(-1, (i + j))) * getPositiveModulus(getMinorMatrix(keyMatrix)[i, j])) % 26));
                    }
                }
            }
            return inverseMatrix;
        }

        private static int[,] getMinorMatrix(int[,] matrix)
        {
            int sqrtMatrixSize = (int)Math.Sqrt(matrix.Length);
            int[,] minorMatrix = new int[sqrtMatrixSize, sqrtMatrixSize];
            if (sqrtMatrixSize > 2)
                for (int i = 0; i < sqrtMatrixSize; i++)
                {
                    for (int j = 0; j < sqrtMatrixSize; j++)
                    {
                        minorMatrix[i, j] = (matrix[((i + 1) % sqrtMatrixSize), ((j + 1) % sqrtMatrixSize)] * matrix[((i + 2) % sqrtMatrixSize), ((j + 2) % sqrtMatrixSize)] - matrix[((i + 1) % sqrtMatrixSize), ((j + 2) % sqrtMatrixSize)] * matrix[((i + 2) % sqrtMatrixSize), ((j + 1) % sqrtMatrixSize)]);
                    }
                }
            else
            {
                return reverse2_DMatrix(matrix);
            }
            return minorMatrix;
        }
        public static int[,] reverse2_DMatrix(int[,] matrix)
        {
            int[,] reversedMatrix = new int[2, 2];
            reversedMatrix[0, 0] = matrix[1, 1];
            reversedMatrix[0, 1] = matrix[1, 0];
            reversedMatrix[1, 1] = matrix[0, 0];
            reversedMatrix[1, 0] = matrix[0, 1];
            return reversedMatrix;

        }
        public static int[,] makeTwoDimensionKeyMatrix(List<int> oneDimenesionKey)
        {
            int keySize = (int)Math.Sqrt(oneDimenesionKey.Count);
            int[,] twoDemensionMatrix = new int[keySize, keySize];
            int letterIndex = 0;
            for (int rowIndex = 0; rowIndex < keySize; rowIndex++)
            {
                for (int columnIndex = 0; columnIndex < keySize; columnIndex++)
                {
                    twoDemensionMatrix[rowIndex, columnIndex] = oneDimenesionKey[letterIndex];
                    letterIndex++;
                }
            }
            return twoDemensionMatrix;
        }
        public static int[,] makeTwoDimensionPlainMatrix(List<int> oneDimenesionPlainText, int rowsSize)
        {
            int columnsNum = oneDimenesionPlainText.Count / rowsSize;
            int letterIndex = 0;
            int[,] twoDemensionMatrix = new int[rowsSize, columnsNum];
            for (int column = 0; column < columnsNum; column++)
            {
                for (int row = 0; row < rowsSize; row++)
                {
                    twoDemensionMatrix[row, column] = oneDimenesionPlainText[letterIndex];
                    letterIndex++;
                }
            }

            return twoDemensionMatrix;
        }
        public static List<int> getProductOfTwoMatrices(List<int> PlainTextMatrix, int[,] keyMatrix)
        {
            int sqrtKeySize = (int)Math.Sqrt(keyMatrix.Length);
            List<int> product = new List<int>();
            for (int rowIndex = 0; rowIndex < sqrtKeySize; rowIndex++)
            {
                int rowByColumnProduct = 0;
                for (int columnIndex = 0; columnIndex < sqrtKeySize; columnIndex++)
                    rowByColumnProduct += keyMatrix[rowIndex, columnIndex] * PlainTextMatrix[columnIndex];
                rowByColumnProduct %= 26;
                while (rowByColumnProduct < 0)
                    rowByColumnProduct += 26;
                product.Add(rowByColumnProduct);
            }
            return product;
        }

        public  List<int> Encrypt(List<int> plainText, List<int> key)
        {
            int sqrtKeySize = (int)Math.Sqrt(key.Count);
            List<int> cipher = new List<int>();
            int[,] plainTextMatrix = makeTwoDimensionPlainMatrix(plainText, sqrtKeySize);
            int[,] keyMatrix = makeTwoDimensionKeyMatrix(key);
            for (int column = 0; column < plainText.Count / sqrtKeySize; column++)
            {
                List<int> PlainTextColumn = new List<int>();
                for (int row = 0; row < sqrtKeySize; row++)
                    PlainTextColumn.Add(plainTextMatrix[row, column]);
                List<int> columnByMatrixProduct = getProductOfTwoMatrices(PlainTextColumn, keyMatrix);
                for (int i = 0; i < sqrtKeySize; i++)
                    cipher.Add(columnByMatrixProduct[i]);
            }
            return cipher;
        }
        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            List<int> key = new List<int>();

            for (int index = 0, count = 2; index < 2; index++, count += 2)
            {
                for (int result1 = 0; result1 < 26; result1++)
                {
                    for (int result2 = 0; result2 < 26; result2++)
                    {
                        if (((result1 * plainText[0]) + (result2 * plainText[1])) % 26 == cipherText[index] &&
                            ((result1 * plainText[2]) + (result2 * plainText[3])) % 26 == cipherText[index + 2])
                        {
                            key.Add(result1);
                            key.Add(result2);
                            break;
                        }
                    }
                    if (key.Count == count)
                        break;
                }
            }

            if (key.Count < 4)
                throw new InvalidAnlysisException();
            return key;
        }

        public string Analyse(string plainText, string cipherText)
        {
            throw new NotImplementedException();
        }

        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            int sqrtKeySize = (int)Math.Sqrt(key.Count);
            List<int> plain = new List<int>();
            int[,] cipherTextMatrix = makeTwoDimensionPlainMatrix(cipherText, sqrtKeySize);
            int[,] keyMatrix = makeTwoDimensionKeyMatrix(key);
            keyMatrix = getMatrixTranspose(calculateMultiplicativeInverse(keyMatrix));
            for (int column = 0; column < cipherText.Count / sqrtKeySize; column++)
            {
                List<int> cipherTextColumn = new List<int>();
                for (int row = 0; row < sqrtKeySize; row++)
                    cipherTextColumn.Add(cipherTextMatrix[row, column]);
                List<int> columnByMatrixProduct = getProductOfTwoMatrices(cipherTextColumn, keyMatrix);
                for (int i = 0; i < sqrtKeySize; i++)
                    plain.Add(columnByMatrixProduct[i]);
            }
            return plain;
        }

        public string Decrypt(string cipherText, string key)
        {
            throw new NotImplementedException();
        }



        public string Encrypt(string plainText, string key)
        {
            throw new NotImplementedException();
        }
        public List<int> Analyse2By2Key(List<int> plain3, List<int> cipher3)
        {
            throw new NotImplementedException();
        }
        public string Analyse2By2Key(string plain3, string cipher3)
        {
            throw new NotImplementedException();
        }
        public List<int> Analyse3By3Key(List<int> plainText, List<int> cipherText)
        {
            List<int> key = new List<int>();
            for (int index = 0, count = 3; index < 3; index++, count += 3)
            {
                for (int result1 = 0; result1 < 26; result1++)
                {
                    for (int result2 = 0; result2 < 26; result2++)
                    {
                        for (int result3 = 0; result3 < 26; result3++)
                        {
                            if (((result1 * plainText[0]) + (result2 * plainText[1]) + (result3 * plainText[2])) % 26 == cipherText[index] &&
                                ((result1 * plainText[3]) + (result2 * plainText[4]) + (result3 * plainText[5])) % 26 == cipherText[index + 3] &&
                                ((result1 * plainText[6]) + (result2 * plainText[7]) + (result3 * plainText[8])) % 26 == cipherText[index + 6])
                            {
                                key.Add(result1);
                                key.Add(result2);
                                key.Add(result3);
                                break;
                            }
                        }
                        if (key.Count == count)
                            break;
                    }
                    if (key.Count == count)
                        break;
                }
            }
            return key;
        }

        public string Analyse3By3Key(string plain3, string cipher3)
        {
            throw new NotImplementedException();
        }
    }
}
