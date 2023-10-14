using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class AES : CryptographicTechnique
    {
        byte[,] sbox = new byte[16, 16] {   {0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76},
                                            {0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0},
                                            {0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15},
                                            {0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75},
                                            {0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84},
                                            {0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF},
                                            {0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8},
                                            {0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2},
                                            {0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73},
                                            {0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB},
                                            {0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79},
                                            {0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08},
                                            {0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A},
                                            {0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E},
                                            {0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF},
                                            {0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16} };
        static byte[,] sboxInverse = new byte[16, 16] { { 0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb },
                                                        { 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb },
                                                        { 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e },
                                                        { 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25 },
                                                        { 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92 },
                                                        { 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84 },
                                                        { 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06 },
                                                        { 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b },
                                                        { 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73 },
                                                        { 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e },
                                                        { 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b },
                                                        { 0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4 },
                                                        { 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f },
                                                        { 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef },
                                                        { 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61 },
                                                        { 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d } };

        int Rcon_index = 0;
        byte[,] Rcon = new byte[4, 10] { {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 },
                                         {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
                                         {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
                                         {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }};

        byte[,] galoisField = new byte[4, 4] {  {0x02, 0x03, 0x01, 0x01},
                                                {0x01, 0x02, 0x03, 0x01},
                                                {0x01, 0x01, 0x02, 0x03},
                                                {0x03, 0x01, 0x01, 0x02}};

        byte[,] galoisFieldInverse = new byte[4, 4] {   {0x0e, 0x0b, 0x0d, 0x09},
                                                        {0x09, 0x0e, 0x0b, 0x0d},
                                                        {0x0d, 0x09, 0x0e, 0x0b},
                                                        {0x0b, 0x0d, 0x09, 0x0e}};
        static byte[,] key_expansion = new byte[44, 4];
        private static byte[] rotateByOne(byte[] words) //True
        {
            byte firstElement = words[0];
            for (int i = 0; i < words.Length - 1; i++)
                words[i] = words[i + 1];
            words[words.Length - 1] = firstElement;
            return words;
        }
        byte[] subByte(byte[] word) // True
        {
            int arraySize = 4;
            byte[] result = new byte[arraySize];
            int newRow , newColumn;
            
            for (int i = 0; i < 4; i++)
            {
                string tempword = Convert.ToString(word[i], 16);
                if (tempword.Length == 1)
                {
                    newRow = 0;
                    newColumn = Convert.ToInt32(tempword[0].ToString(), 16);
                }
                else
                {
                    newRow = Convert.ToInt32(tempword[0].ToString(), 16);
                    newColumn = Convert.ToInt32(tempword[1].ToString(), 16);
                }
                result[i] = sbox[newRow, newColumn];
            }
            return result;
        }
        private static byte[] XOR(byte[] x, byte[] y, byte[] z, bool isMultipleOfFour) //True
        {
            byte[] result = new byte[4];
            for (int i = 0; i < 4; i++)
            {
                byte tempResult;
                if (isMultipleOfFour)
                    tempResult = (byte)(x[i] ^ y[i] ^ z[i]);
                else
                    tempResult = (byte)(x[i] ^ y[i]);
                result[i] = tempResult;
            }
            return result;
        }

        string makeMatrixString(byte[,] matrix) //True
        {
            StringBuilder word = new StringBuilder();
            for (int row = 0; row < 4; row++)
            {
                for (int column = 0; column < 4; column++)
                {
                    string temp = Convert.ToString(matrix[column, row], 16);
                    if (temp.Length >= 2)
                        word.Append(temp);
                    else
                        word.Append("0" + temp);
                }
            }
            return word.ToString().ToUpper().Insert(0, "0x");
        }

        private static byte[,] convertStrinToByte(string word)//True
        {
            int matrixSize = 4;
            byte[,] matrix = new byte[matrixSize, matrixSize];
            int k = 0;
            for (int row = 0; row < matrixSize; row++)
            {
                for (int column = 0; column < matrixSize; column++)
                {
                    k += 2;
                    string temp = "0x" + word[k] + word[k + 1];
                    matrix[column, row] = Convert.ToByte(temp, 16);
                    
                }
            }
            return matrix;
        }

        private static byte[,] convertStrinToByteInverse(string word)//True
        {
            int matrixSize = 4;
            byte[,] matrix = new byte[matrixSize, matrixSize];
            int k = 0;
            for (int row = 0; row < matrixSize; row++)
            {
                for (int column = 0; column < matrixSize; column++)
                {
                    k += 2;
                    string temp = "0x" + word[k] + word[k + 1];
                    matrix[row, column] = Convert.ToByte(temp, 16);

                }
            }
            return matrix;
        }

        void fillKey(string key) //True
        {
            byte[,] keyArray = new byte[4, 4];
            keyArray = convertStrinToByteInverse(key);
            for (int row = 0; row < 4; row++)
                for (int column = 0; column < 4; column++)
                    key_expansion[row,column] = keyArray[row, column];
        }
        byte[,] get_key_matrix(int index) //True
        {
            byte[,] matrix = new byte[4, 4];
            int row = 0;
            int i = index * 4;
            while ( i < index * 4 + 4 )
            {
                int column = 0;
                int j = 0;
                while( j < 4)
                {
                    matrix[column, row] = key_expansion[i, j];
                    column++;
                    j++;
                }
                row++;
                i++;
            }
            return matrix;
        }
        byte[,] MakeRoundKey(byte[,] matrix, int Round_index)
        {
            byte[,] key;
            key = get_key_matrix(Round_index);
            byte tmp;
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    tmp = (byte)(key[i, j] ^ matrix[i, j]);
                    key[i, j] = tmp;
                }
            }
            return key;
        } // true
        void makeKeyExpansion() //true
        {
            byte[] x = new byte[4];
            byte[] y = new byte[4];
            byte[] z = new byte[4];
            byte[] final = new byte[4];
            for (int i = 4; i < 44; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    x[j] = key_expansion[i - 1, j];
                    y[j] = key_expansion[i - 4, j];
                    if (Rcon_index < 10)
                        z[j] = Rcon[j, Rcon_index];
                }
                if (i % 4 == 0)
                {
                    // Console.WriteLine(i);
                    Rcon_index++;
                    x = rotateByOne(x);
                    x = subByte(x);
                    final = XOR(x, y, z, true);
                }
                else
                    final = XOR(x, y, z, false);

                for (int j = 0; j < 4; j++)
                {
                    // Console.Write(key_expansion[i,j]);
                    key_expansion[i, j] = final[j];
                }

            }
        }
        void print_key_matrix()
        {
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 44; j++)
                {
                    Console.Write(string.Join(", ", key_expansion[j, i].ToString("X2")));
                    Console.Write(" ");
                }
                Console.WriteLine();
            }
        }
        void print_mat(byte[,] mat)
        {

            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    Console.Write(string.Join(", ", mat[i, j].ToString("X2")));
                    Console.Write(" ");
                }
                Console.WriteLine();
            }

            Console.WriteLine("");
        }
        byte multiplybyTwo(byte x) //true
        {
            byte result;
            byte temp = (byte)(x << 1);
            result = (byte)(temp & 0xFF);
            if (x > 127)
                result = (byte)(result ^ 27);
            return result;
        }

        byte[,] mixColumns(byte[,] matrix)
        {
            byte[] arrayXor = new byte[4];
            byte[,] mixedColumnsMatrix= new byte[4, 4];
            for (int rows = 0; rows < 4; rows++)
            {
                for (int columns = 0; columns < 4; columns++)
                {
                    for (int k = 0; k < 4; k++)
                    {
                        if (galoisField[columns, k] == 2)
                            arrayXor[k] = multiplybyTwo(matrix[k, rows]);
                        if (galoisField[columns, k] == 3)
                            arrayXor[k] = (byte)(multiplybyTwo(matrix[k, rows]) ^ matrix[k, rows]);

                        if (galoisField[columns, k] == 1)
                            arrayXor[k] = matrix[k, rows];
                    }
                    byte cell = (byte)(arrayXor[0] ^ arrayXor[1] ^ arrayXor[2] ^ arrayXor[3]);
                    mixedColumnsMatrix[columns, rows] = cell;
                }
            }
            return mixedColumnsMatrix;
        } // true

        
        byte[,] mixColsInverse(byte[,] shiftedmatrix)
        {
            byte[] arrayXor = new byte[4];
            byte[,] mixedColumnsMatrix = new byte[4, 4];
            for (int row = 0; row < 4; row++)
            {
                for (int column = 0; column < 4; column++)
                {
                    for (int k = 0; k < 4; k++)
                    {
                        if (galoisFieldInverse[column, k] == 0x9)
                        {
                            byte x0 = shiftedmatrix[k, row];
                            byte x1 = multiplybyTwo(x0);
                            byte x2 = multiplybyTwo(x1);
                            byte x3 = multiplybyTwo(x2);
                            arrayXor[k] =(byte)(x3 ^ x0);
                        }
                        if (galoisFieldInverse[column, k] == 0xB)
                        {
                            byte x0 = shiftedmatrix[k, row];
                            byte x1 = multiplybyTwo(x0);
                            byte x2 = multiplybyTwo(x1);
                            byte x3 = multiplybyTwo(x2);
                            arrayXor[k] = (byte)(x3 ^ x0 ^ x1);
                        }
                        if (galoisFieldInverse[column, k] == 0xD)
                        {
                            byte x0 = shiftedmatrix[k, row];
                            byte x1 = multiplybyTwo(x0);
                            byte x2 = multiplybyTwo(x1);
                            byte x3 = multiplybyTwo(x2);
                            arrayXor[k] = (byte)(x3 ^ x2 ^ x0);
                        }

                        if (galoisFieldInverse[column, k] == 0xE)
                        {
                            byte x0 = shiftedmatrix[k, row];
                            byte x1 = multiplybyTwo(x0);
                            byte x2 = multiplybyTwo(x1);
                            byte x3 = multiplybyTwo(x2);
                            arrayXor[k] = (byte)(x3 ^ x2 ^ x1);
                        }
                    }
                    var cell = arrayXor[0] ^ arrayXor[1] ^ arrayXor[2] ^ arrayXor[3];
                    mixedColumnsMatrix[column, row] = (byte)(cell);
                }
            }
            return mixedColumnsMatrix;
        } // true

        byte[,] makeIntialRound(byte[,] stateMatrix)
        {
            for (int row = 0; row < 4; row++)
            {
                for (int column = 0; column < 4; column++)
                    stateMatrix[column, row] = (byte)(stateMatrix[column, row] ^ key_expansion[row, column]);
            }
            return stateMatrix;
        } // true
        byte[,] substituteMatrix(byte[,] oldMatrix)
        {
            byte[,] newMatrix = new byte[4, 4];
            for (int row = 0; row < 4; row++)
            {
                for (int column = 0; column < 4; column++)
                {
                    string tmp = Convert.ToString(oldMatrix[row, column], 16);
                    int newRow, newColumn;
                    if (tmp.Length != 1)
                    {
                        newRow = Convert.ToInt32(tmp[0].ToString(), 16);
                        newColumn = Convert.ToInt32(tmp[1].ToString(), 16);
                     
                    }
                    else
                    {
                        newRow = 0;
                        newColumn = Convert.ToInt32(tmp[0].ToString(), 16);
                    }


                    newMatrix[row, column] = sbox[newRow, newColumn];
                }
            }
            return newMatrix;
        }// true
        byte[,] substituteMatrixInverse(byte[,] matrix)
        {
            byte[,] newMatrix = new byte[4, 4];
            for (int row = 0; row < 4; row++)
            {
                for (int column = 0; column < 4; column++)
                {
                    string tmp = Convert.ToString(matrix[row, column], 16);
                    int newRow, newColumn;
                    if (tmp.Length != 1)
                    {
                        newRow = Convert.ToInt32(tmp[0].ToString(), 16);
                        newColumn = Convert.ToInt32(tmp[1].ToString(), 16);
                 
                    }
                    else
                    {
                        newRow = 0;
                        newColumn = Convert.ToInt32(tmp[0].ToString(), 16);
                    }


                    newMatrix[row, column] = sboxInverse[newRow, newColumn];
                }
            }
            return newMatrix;
        }//true

       
        byte[] shiftRow(byte[] row, int n)
        {
            UInt32 x = 0;
            for (int j = 0; j < 4; j++)
            {

                x += Convert.ToUInt32(row[j]);
                if (j != 3) x <<= 8;
            }
            x = (x << (n * 8)) | (x) >> (32 - (n * 8));

            byte[] newRow = new byte[4];
            int i = 3;
            while (i >= 0)
            {
                newRow[i] = (byte)(x & 0xFF);
                x >>= 8;
                i--;
            }
            return newRow;
        } // true
        byte[,] shiftMatrix(byte[,] matrix)  //true
        {
            byte[,] newMatrix = new byte[4, 4];
            byte[] row = new byte[4];
            int i = 0;
            while(i < 4)
            {
                int j = 0;
                while( j < 4)
                {
                    row[j] = matrix[i, j];
                    j++;
                }
                row = shiftRow(row, i);
                 j = 0;
                while(j < 4 )
                {
                    newMatrix[i, j] = row[j];
                    j++;
                }
                i++;
            }
            return newMatrix;
        }
        byte[] shiftRowInverse(byte[] row, int n) //true
        {
            UInt32 number = 0;
            int i = 0;
            while ( i < 4)
            {

                number += Convert.ToUInt32(row[i]);
                if (i != 3) 
                    number = number << 8;
                i++;
            }
            number = ((number >> (n * 8)) | (number) << (32 - (n * 8)));

            byte[] newRow = new byte[4];
            i = 3;
            while ( i >= 0)
            {
                newRow[i] = (byte)(number & 0xFF);
                number = number >> 8;
                i--;
            }
            return newRow;
        }
        byte[,] shiftMatrixInverse(byte[,] matrix) // true
        {
            byte[,] newMatrix = new byte[4, 4];
            byte[] row = new byte[4];
            int i = 0;
            while (i < 4)
            {
                int j = 0;
                while (j < 4)
                {
                    row[j] = matrix[i, j];
                    j++;
                }
                row = shiftRowInverse(row, i);
                j = 0;
                while (j < 4)
                {
                    newMatrix[i, j] = row[j];
                    j++;
                }
                i++;
            }
            return newMatrix;
        }
        byte[,] finalRoundEncrypt(byte[,] stateMatrix) //true
        {
            stateMatrix = substituteMatrix(stateMatrix);
            
            stateMatrix = shiftMatrix(stateMatrix);
           
            stateMatrix = MakeRoundKey(stateMatrix, 10);
           
            return stateMatrix;
        }
        byte[,] finalRoundDecrypt(byte[,] stateMatrix) //true
        {
            stateMatrix = MakeRoundKey(stateMatrix, 10);
           
            stateMatrix = shiftMatrixInverse(stateMatrix);
            
            stateMatrix = substituteMatrixInverse(stateMatrix);
            
            return stateMatrix;
        }
        byte[,] mainRoundsEncrypt(byte[,] stateMatrix, int round) //true
        {
            stateMatrix = substituteMatrix(stateMatrix);
            stateMatrix = shiftMatrix(stateMatrix);
            stateMatrix = mixColumns(stateMatrix);
            stateMatrix = MakeRoundKey(stateMatrix, round);
            return stateMatrix;
        }
        byte[,] main_rounds_decryption(byte[,] stateMatrix, int round)//true
        {
            stateMatrix = MakeRoundKey(stateMatrix, round);
            stateMatrix = mixColsInverse(stateMatrix);
            stateMatrix = shiftMatrixInverse(stateMatrix);
            stateMatrix = substituteMatrixInverse(stateMatrix);
            return stateMatrix;
        }
        byte[,] firstRoundDecryption(byte[,] stateMatrix)//true
        {
            stateMatrix = MakeRoundKey(stateMatrix, 0);
            return stateMatrix;
        }
        public override string Decrypt(string cipherText, string key)
        {

            byte[,] state = convertStrinToByte(cipherText);
            fillKey(key);
            makeKeyExpansion();
            state = finalRoundDecrypt(state);

            for (int i = 9; i > 0; i--)
                state = main_rounds_decryption(state, i);

            state = firstRoundDecryption(state);
            return makeMatrixString(state);
        }

        public override string Encrypt(string plainText, string key)
        {
            byte[,] state = convertStrinToByte(plainText);
            fillKey(key);
            makeKeyExpansion();
            state = makeIntialRound(state);

            for (int i = 1; i < 10; i++)
                state = mainRoundsEncrypt(state, i);
            state = finalRoundEncrypt(state);
            return makeMatrixString(state);
        }
    }
}