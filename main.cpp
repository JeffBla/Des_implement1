#include <iostream>
#include <bitset>
#include <iterator>
#include <vector>
#include <cmath>

using namespace std;

class DES_encryption {
private:
    const int KP[56] = {57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
                        10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
                        63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
                        14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4};

    const int leftShift_table[16] = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};

    const int CP[48] = {14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10,
                        23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
                        41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
                        44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32};

    const int IP[64] = {58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
                        62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
                        57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
                        61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7};

    const int EP[48] = {32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9,
                        8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
                        16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
                        24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1};

    const int SBOX[8][4][16] = {                        // S-box
            {
                    {14, 4,  13, 1,  2,  15, 11, 8,  3,  10, 6,  12, 5,  9,  0,  7},
                    {0,  15, 7,  4,  14, 2,  13, 1,  10, 6, 12, 11, 9,  5,  3,  8},
                    {4,  1,  14, 8,  13, 6,  2,  11, 15, 12, 9,  7,  3,  10, 5,  0},
                    {15, 12, 8,  2,  4,  9,  1,  7,  5,  11, 3,  14, 10, 0, 6,  13}
            },
            {
                    {15, 1,  8,  14, 6,  11, 3,  4,  9,  7,  2,  13, 12, 0,  5,  10},
                    {3,  13, 4,  7,  15, 2,  8,  14, 12, 0, 1,  10, 6,  9,  11, 5},
                    {0,  14, 7,  11, 10, 4,  13, 1,  5,  8,  12, 6,  9,  3,  2,  15},
                    {13, 8,  10, 1,  3,  15, 4,  2,  11, 6,  7,  12, 0,  5, 14, 9}
            },
            {
                    {10, 0,  9,  14, 6,  3,  15, 5,  1,  13, 12, 7,  11, 4,  2,  8},
                    {13, 7,  0,  9,  3,  4,  6,  10, 2,  8, 5,  14, 12, 11, 15, 1},
                    {13, 6,  4,  9,  8,  15, 3,  0,  11, 1,  2,  12, 5,  10, 14, 7},
                    {1,  10, 13, 0,  6,  9,  8,  7,  4,  15, 14, 3,  11, 5, 2,  12}
            },
            {
                    {7,  13, 14, 3,  0,  6,  9,  10, 1,  2,  8,  5,  11, 12, 4,  15},
                    {13, 8,  11, 5,  6,  15, 0,  3,  4,  7, 2,  12, 1,  10, 14, 9},
                    {10, 6,  9,  0,  12, 11, 7,  13, 15, 1,  3,  14, 5,  2,  8,  4},
                    {3,  15, 0,  6,  10, 1,  13, 8,  9,  4,  5,  11, 12, 7, 2,  14}
            },
            {
                    {2,  12, 4,  1,  7,  10, 11, 6,  8,  5,  3,  15, 13, 0,  14, 9},
                    {14, 11, 2,  12, 4,  7,  13, 1,  5,  0, 15, 10, 3,  9,  8,  6},
                    {4,  2,  1,  11, 10, 13, 7,  8,  15, 9,  12, 5,  6,  3,  0,  14},
                    {11, 8,  12, 7,  1,  14, 2,  13, 6,  15, 0,  9,  10, 4, 5,  3}
            },
            {
                    {12, 1,  10, 15, 9,  2,  6,  8,  0,  13, 3,  4,  14, 7,  5,  11},
                    {10, 15, 4,  2,  7,  12, 9,  5,  6,  1, 13, 14, 0,  11, 3,  8},
                    {9,  14, 15, 5,  2,  8,  12, 3,  7,  0,  4,  10, 1,  13, 11, 6},
                    {4,  3,  2,  12, 9,  5,  15, 10, 11, 14, 1,  7,  6,  0, 8,  13}
            },
            {
                    {4,  11, 2,  14, 15, 0,  8,  13, 3,  12, 9,  7,  5,  10, 6,  1},
                    {13, 0,  11, 7,  4,  9,  1,  10, 14, 3, 5,  12, 2,  15, 8,  6},
                    {1,  4,  11, 13, 12, 3,  7,  14, 10, 15, 6,  8,  0,  5,  9,  2},
                    {6,  11, 13, 8,  1,  4,  10, 7,  9,  5,  0,  15, 14, 2, 3,  12}
            },
            {
                    {13, 2,  8,  4,  6,  15, 11, 1,  10, 9,  3,  14, 5,  0,  12, 7},
                    {1,  15, 13, 8,  10, 3,  7,  4,  12, 5, 6,  11, 0,  14, 9,  2},
                    {7,  11, 4,  1,  9,  12, 14, 2,  0,  6,  10, 13, 15, 3,  5,  8},
                    {2,  1,  14, 7,  4,  10, 8,  13, 15, 12, 9,  0,  3,  5, 6,  11}
            }
    };

    const int P_Box[32] = {16, 7, 20, 21,
                           29, 12, 28, 17,
                           1, 15, 23, 26,
                           5, 18, 31, 10,
                           2, 8, 24, 14,
                           32, 27, 3, 9,
                           19, 13, 30, 6,
                           22, 11, 4, 25};

    const int Final_P[64] = {40, 8, 48, 16, 56, 24, 64, 32,
                             39, 7, 47, 15, 55, 23, 63, 31,
                             38, 6, 46, 14, 54, 22, 62, 30,
                             37, 5, 45, 13, 53, 21, 61, 29,
                             36, 4, 44, 12, 52, 20, 60, 28,
                             35, 3, 43, 11, 51, 19, 59, 27,
                             34, 2, 42, 10, 50, 18, 58, 26,
                             33, 1, 41, 9, 49, 17, 57, 25};
private:
    vector<string> strKey;

    string *strArr_forLeftAndRight = new string[2];
    string strArr_afterIPLeftAndRight[2];

    string *strToBin(string &secret_key);

    string *addOddParity(string *binStr);

    string *do_KP(string *binStr);

    void leftShift(int round);

    string &do_CP();

    string *generateKey(string &secret_key);

    string *do_IP(string *binStr);

    string *encryptFunc(int round);

public:
    string *encrypt_DSE(string &secret_key, string &plainText);

};

int main() {
//    string secret_key;
//    cout << "Please input the key:" << endl;
//    cin >> secret_key;

    DES_encryption des;
    string strKey("science"), plainText("security");
//    string *tmp = des.strToBin(str);
//    cout << *tmp << endl;
//    des.addOddParity(tmp);
//    cout << *tmp << endl;
//    tmp = des.do_KP(tmp);
//    cout << *tmp << endl;
//    cout << des.strArr_forLeftAndRight[0] << endl;
//    cout << des.strArr_forLeftAndRight[1] << endl;
//    des.leftShift(1);
//    cout << des.strArr_forLeftAndRight[0] << endl;
//    cout << des.strArr_forLeftAndRight[1] << endl;
//    string &tmp_ref = des.do_CP();
//    cout << tmp_ref << endl;

    des.encrypt_DSE(strKey, plainText);

    return 0;
}

string *DES_encryption::strToBin(string &secret_key) {
    auto b = new string;
    for (char ch: secret_key) {
        int num = static_cast<int>(ch);
        string tmp;
        while (num != 0) {
            tmp.append(1, static_cast<char>(num % 2) + '0');
            num /= 2;
        }
        tmp.append(8 - tmp.size(), '0');
        b->append(tmp.rbegin(), tmp.rend());
    }
    return b;
}

string *DES_encryption::addOddParity(string *binStr) {
    int count_bin = 0;
    int count_odd = 0;
    for (int i = 0; i != binStr->size(); i++) {
        count_bin++;

        if (count_bin % 8 == 0 and count_bin != 0) {
            if (count_odd % 2 != 0)
                binStr->insert(i, "0");
            else
                binStr->insert(i, "1");
            count_odd = 0;
            count_bin = 0;
            continue;
        }
        count_odd += (binStr->at(i)) - '0';
    }

    if (count_odd % 2 != 0)
        binStr->append(1, '0');
    else
        binStr->append(1, '1');

    return binStr;
}

string *DES_encryption::do_KP(string *binStr) {
    char afterKP_cStr[57];
    for (int i = 0; i < 56; i++) {
        afterKP_cStr[i] = binStr->at(KP[i] - 1);
    }

    afterKP_cStr[56] = '\0';
    auto afterKP = new string(afterKP_cStr);
    copy(afterKP->begin(), afterKP->begin() + 28, back_inserter((strArr_forLeftAndRight[0])));
    copy(afterKP->begin() + 28, afterKP->end(), back_inserter(strArr_forLeftAndRight[1]));

    delete binStr;
    return afterKP;
}

void DES_encryption::leftShift(int round) {
    char firstAndSecondNum[2];
    // left first
    for (int j = 0; j != 2; j++) {
        for (int i = 0; i != strArr_forLeftAndRight[j].size(); i++) {
            if (i - leftShift_table[round - 1] < 0) {
                firstAndSecondNum[i] = strArr_forLeftAndRight[j][i];
                continue;
            }
            strArr_forLeftAndRight[j][i - leftShift_table[round - 1]] = strArr_forLeftAndRight[j][i];
        }

        if (leftShift_table[round - 1] == 2) {
            strArr_forLeftAndRight[j][strArr_forLeftAndRight[j].size() - 1 - 1] = firstAndSecondNum[0];
            strArr_forLeftAndRight[j][strArr_forLeftAndRight[j].size() - 1] = firstAndSecondNum[1];
        }
        else {
            strArr_forLeftAndRight[j][strArr_forLeftAndRight[j].size() - 1] = firstAndSecondNum[0];
        }
    }
}

string &DES_encryption::do_CP() {
    auto *afterCP = new string;
    // left first
    for (int i = 0; i < 48; i++) {
        if (CP[i] - 1 >= 28) {
            afterCP->append(1, strArr_forLeftAndRight[1][CP[i] - 1 - 28]);
            continue;
        }
        afterCP->append(1, strArr_forLeftAndRight[0][CP[i] - 1]);
    }

    return *afterCP;
}

string *DES_encryption::generateKey(string &secret_key) {
    string *binString = strToBin(secret_key);
    addOddParity(binString);
    string *afterKP = do_KP(binString);

    for (int i = 0; i < 16; i++) {
        leftShift(i + 1);
        strKey.push_back(do_CP());
    }

//   //print 16 Keys
//    for (auto &str: strKey) {
//        cout << str << endl;
//    }
    return nullptr;
}

string *DES_encryption::do_IP(string *binStr) {
    auto *afterIP = new string;
    for (int i = 0; i < 64; i++) {
        afterIP->append(1, binStr->at(IP[i] - 1));
    }

    copy(afterIP->begin(), afterIP->begin() + 32, back_inserter(strArr_afterIPLeftAndRight[0]));
    copy(afterIP->begin() + 32, afterIP->end(), back_inserter(strArr_afterIPLeftAndRight[1]));
    return afterIP;
}

string *DES_encryption::encryptFunc(int round) {
    string afterEPAndXor;
    for (int i = 0; i < 48; i++) {
        char afterEP_ch = strArr_afterIPLeftAndRight[1].at(EP[i] - 1);
        if (afterEP_ch == strKey[round - 1][i]) {
            afterEPAndXor.append(1, '0');
        }
        else {
            afterEPAndXor.append(1, '1');
        }
    }

    // S-BOX
    string afterSBox;
    int performTimes = 0;
    int row_index = 0, column_index = 0;
    for (int k = 0; k < 8; k++, performTimes++, column_index = 0) {
        row_index = 2 * (afterEPAndXor[k * 6] - '0') + afterEPAndXor[k * 6 + 5] - '0';
        for (int i = 0; i < 4; i++) {
            column_index += (afterEPAndXor[k * 6 + i + 1] - '0') * pow(2, 3 - i);
        }
        int decNum = SBOX[performTimes][row_index][column_index];
        string tmp;
        while (decNum != 0) {
            tmp.append(1, static_cast<char>(decNum % 2) + '0');
            decNum /= 2;
        }
        tmp.append(4 - tmp.size(), '0');
        afterSBox.append(tmp.rbegin(), tmp.rend());
    }

    // P-BOX
    auto *afterPBox = new string;
    for (int i: P_Box) {
        afterPBox->append(1, afterSBox.at(i - 1));
    }

    return afterPBox;
}

string *DES_encryption::encrypt_DSE(string &secret_key, string &plainText) {
    generateKey(secret_key);

    string *binStr = strToBin(plainText);
    do_IP(binStr);
    for (int j = 0; j < 16; j++) {
        string left(strArr_afterIPLeftAndRight[1]), *right = encryptFunc(j + 1);

        for (int i = 0; i < right->size(); i++) {
            if (right->at(i) != strArr_afterIPLeftAndRight[0].at(i))
                right->at(i) = '1';
            else
                right->at(i) = '0';
        }

        strArr_afterIPLeftAndRight[0].assign(left);
        strArr_afterIPLeftAndRight[1].assign(*right);
        delete right;
    }

    return nullptr;
}



