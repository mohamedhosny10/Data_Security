using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    public class ExtendedEuclid
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="number"></param>
        /// <param name="baseN"></param>
        /// <returns>Mul inverse, -1 if no inv</returns>

        public int GetMultiplicativeInverse(int number, int baseN)
        {
            int a3 = baseN, b2 = 0, b1 = 1;

            while (number >= 1)
            {
                int q = a3 / number;
                int b3 = number;
                number = a3 % number;
                a3 = b3;
                b3 = b1;
                b1 = b2 - q * b3;
                b2 = b3;

            }
            b2 = b2 % baseN;

            if (a3 != 1) return -1;
            if (b2 < 0) b2 = (b2 + baseN) % baseN;

            return b2;
        }
    }
}