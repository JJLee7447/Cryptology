#pragma noce
#include<vector>
#include<algorithm>
#include<bitset>
#include<string>
#include <iostream>

using std::cout;
using std::bitset;
using std::rotate;
using std::string;
using std::vector;

class DES
{
private:
    const static vector<int> IP_table;       //初始置换表
    const static vector<int> IPR_table;      //初始逆置换表
    const static vector<int> E_table;        //E表
    const static vector<int> P_table;        //P置换
    const static vector<int> PC1_table;      //选择置换PC1
    const static vector<int> PC2_table;      //选择置换PC2
    const static vector<vector<vector<int>>> S_table;  //s表
    const static vector<int> Key_move_table;  //循环移动表
    static vector<bool> cipher;                //密文
    static vector<bool> plain;                 //明文
    vector<vector<bool>> En_sub_key;               //加密子密钥
    vector<vector<bool>> De_sub_key;            //解密密子密钥

    void Build_En_Sub_key(const vector<bool> &key);  //生成子密钥
    void Bulid_De_sub_key(const vector<bool> &key); //生成解密子密钥
    vector<bool> IP(const vector<bool> &IN_Plaintext);   //初始置换
    vector<bool> IPR(const vector<bool> &INR_text);          // 初始逆置换
    vector<bool> Expansion(vector<bool> & R);         //Expansion
    int BinToDec(const vector<bool> &data);           //二进制转十进制
    vector<bool> DecToBin(const int &num);            //十进制转二进制
    vector<bool> S_compression(vector<bool> & xor_result);   //S盒压缩
    void En_Round_func(vector<bool> &l, vector<bool> &r);   //加密轮函数
    void De_Round_func(vector<bool> &l, vector<bool> &r); //解密轮函数


    vector<vector<bool>> StrToBinVec(const string &PlianText);   //将字符串转换为 vector<vector<bool>> [n][64]
    string BinVecToStr(const vector<vector<bool>> &PlianText);   //将vector<vector<bool>>[n][64] 转换为string

public:
    vector<bool> bit8_String_To_bit64_VectorBool(const string &PlainText);  //字符串转二进制
    string bit64_VectorBool_To_bit8_String(const vector<bool> &PlianText);  //二进制转字符串
    void DES_Encrypt(const vector<bool> &IN_Plaintext, vector<bool> &OUT_Ciphertext, const vector<bool> &KEY);    //加密
    void DES_Decrypt(vector<bool> &OUT_Plaintext,const vector<bool> &IN_Ciphertext, const vector<bool> &KEY);    //解密

};


/**
 * 盒子定义
*/
const vector<int> DES::IP_table = {
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7};
const vector<int> DES::IPR_table = {
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25};
const vector<int> DES::E_table = {
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1};
const vector<int> DES::P_table = {
    16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25};
const vector<int> DES::PC1_table = {
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4};
const vector<int> DES::PC2_table = {
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32};
const vector<vector<vector<int>>> DES::S_table = {
    // 定义S1盒
    {{14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
     {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
     {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
     {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}},
    // 定义S2盒
    {{15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
     {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
     {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
     {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}},
    // 定义S3盒
    {{10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
     {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
     {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
     {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}},
    // 定义S4盒
    {{7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
     {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
     {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
     {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}},
    // 定义S5盒
    {{2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
     {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
     {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
     {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}},
    // 定义S6盒
    {{12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
     {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
     {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
     {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}},
    // 定义S7盒
    {{4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
     {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
     {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
     {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}},
    // 定义S8盒
    {{13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
     {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
     {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
     {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}}};
const vector<int> DES::Key_move_table = {
    1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};

//字符串转二进制  8个字符 -> 64 bit
vector<bool> DES::bit8_String_To_bit64_VectorBool(const string &PlainText){
    string str(PlainText);
    string binStr;
    int count = str.size();
    while (count<=7)
    {
        str +=' ';
        count++;
    }
    for(char c:str){
        bitset<8> binset(c);
        binStr += binset.to_string();
    }
    vector<bool> binVec;
    for(char c:binStr){
        bool val = (c == '1');
        binVec.push_back(val);
    }
    return binVec;
}

//二进制转字符串
string DES::bit64_VectorBool_To_bit8_String(const vector<bool> &PlianText){
    string Str;
    string binStr;
    for(bool i : PlianText){
        binStr += (i ? '1' : '0');
    }
    for (int i = 0; i < binStr.size();i+=8){
        bitset<8> binSet(binStr.substr(i, 8));
        char c = binSet.to_ulong();
        Str += c;
    }
    return Str;
} 

//二进制转十进制
int DES::BinToDec(const vector<bool> &data) {
    int result = 0;
    for (int i = 0; i < data.size(); i++) {
        result = result * 2 + (data[i] ? 1 : 0);
    }
    return result;
}

//十进制转二进制
vector<bool> DES::DecToBin(const int &num){
    bitset<4> bits(num);
    string bitString = bits.to_string();
    vector<bool> bool_vector;
    for(char c:bitString){
        bool_vector.push_back(c == '1');
    }
    return bool_vector;
}

//将字符串转换为 vector<vector<bool>> [n][64]
vector<vector<bool>> DES::StrToBinVec(const string &PlianText){
    vector<string> VecStr;
    for (auto it = PlianText.begin(); it <= PlianText.end(); it+=8)
    {
        string str(it, it + 7);
        VecStr.push_back(str);
    }
    vector<vector<bool>> result;
    for (int i = 0; i < VecStr.size();i++){
        result.push_back(bit8_String_To_bit64_VectorBool(VecStr[i]));
    }
    return result;
}  

//将vector<vector<bool>>[n][64] 转换为string
string DES::BinVecToStr(const vector<vector<bool>> &PlianText){
    string result;
    for (int i = 0; i < PlianText.size();i++){
        result += bit64_VectorBool_To_bit8_String(PlianText[i]);
    }
    return result;
}

//初始置换
vector<bool> DES::IP(const vector<bool>& IN_Plaintext){
    vector<bool> text;
    for (int i = 0; i < IN_Plaintext.size(); i++)
    {
        text.push_back(IN_Plaintext[IP_table[i]-1]);
    }
    return text;
}

//初始逆置换
vector<bool> DES::IPR(const vector<bool> &IPR_text){
    vector<bool> text;
    for (int i = 0; i < IPR_text.size(); i++)
    {
        text.push_back(IPR_text[IPR_table[i]-1]);
    }
    return text;
}

//Expansion Permutation
vector<bool> DES::Expansion(vector<bool> &R){
    vector<bool> result(48);
    for (int i = 0; i < 48;i++){
        result[i] = R[E_table[i] - 1];
    }
    return result;
}

//S盒压缩
vector<bool> DES::S_compression(vector<bool> & xor_result){  //48bit -> 32bit
    
    // 分组Groups[8][6]
    vector<vector<bool>> Groups(8, vector<bool>(6));
    int index = 0;
    for (int i = 0; i < 48; i += 6) {
        for (int j = 0; j < 6; j++) {
            Groups[index][j] = xor_result[i + j]; // 将6个元素分为一组，插入到二维 vector 中
        }
        index++; // 继续下一组
    }
    // 压缩分组Groups_[8][4]
    vector<vector<bool>> Groups_;
    for (int i = 0; i < 8; i++){
        int row_index = Groups[i][0] *2 + Groups[i][5] *1;
        int col_index = Groups[i][1] * 8 + Groups[i][2] * 4 + Groups[i][3] * 2 + Groups[i][4] * 1;

        int DEC_value = S_table[i][row_index][col_index];

        vector<bool> vec = DecToBin(DEC_value);
        Groups_.push_back(vec);
    }
    // 分组合并 result[32]
    vector<bool> result;
    for (int i = 0; i <Groups_.size(); i++)
    {
        for (int j = 0; j < Groups_[i].size(); j++)
        {
            result.push_back(Groups_[i][j]);
        }
        
    }
    return result;
}

//加密子密钥生成
void DES::Build_En_Sub_key(const vector<bool> &key){
    /*
    //去除校验位
    vector<bool> k(key);
    for (int i = 63; i >= 0; i--) {
        if ((i + 1) % 8 == 0) {  // 判断是否为要删除的元素
            k.erase(k.begin() + i);
        }
    }
    */
    //PC1_table 置换
    vector<bool> k_pc1;
    for (int i = 0; i < PC1_table.size();i++){
        k_pc1.push_back(key[PC1_table[i]-1]);
    }
    //裂开C0,D0
    vector<bool> Ci(k_pc1.begin(), k_pc1.begin() + k_pc1.size() / 2);
    vector<bool> Di(k_pc1.begin() + k_pc1.size() / 2 , k_pc1.end());
    //循环左移生成Ci,Di
    for (int i = 0; i < 16;i++){
        //循环左移
        rotate(Ci.begin(), Ci.begin() + Key_move_table[i], Ci.end());
        rotate(Di.begin(), Di.begin() + Key_move_table[i], Di.end());
        //合并Ci,Di
        vector<bool> merged;
        merged.reserve(Ci.size() + Di.size());
        merged.insert(merged.end(), Ci.begin(), Ci.end());
        merged.insert(merged.end(), Di.begin(), Di.end());
        //PC_2table置换
        vector<bool> K_pc2;
        for (int i = 0; i < 48; i++){
            //cout << "debug in for in "<<i<<"\n";
            K_pc2.push_back(merged[PC2_table[i]-1]);
        }
        //插入每一轮的子密钥
        //法一
        En_sub_key.insert(En_sub_key.end(), {merged});
        /**
         * 法二
         * sub_key.push_back(merged);
      
         */
    }
}

//En_Round func
void DES::En_Round_func(vector<bool> &l,vector<bool> &r){
    for (int i = 0; i < 16; i++)
    {
        //E扩展
        vector<bool> E_r = Expansion(r);
        // XOR
        //cout << "time: " << i << '\n';
        vector<bool> XOR;
        for (int j = 0; j < 48; j++)
        {
            XOR.push_back(E_r[j] ^ En_sub_key[i][j]);
           //cout << En_sub_key[i][j]<<' ';
        }
        //cout << '\n';
        //S盒
        vector<bool> S_result;
        S_result = S_compression(XOR);
        //P置换
        vector<bool> P_result;
        for (int j = 0; j < S_result.size(); j++)
        {
            P_result.push_back(S_result[P_table[j]-1]);
        }
        //l XOR P_result
        vector<bool> R_next;
        for (int j = 0; j < l.size(); j++)
        {
            R_next.push_back(l[j] ^ P_result[j]);
        }

        l = r;
        r = R_next;
    }
}

//加密
void DES::DES_Encrypt(const vector<bool> &IN_Plaintext, vector<bool> &OUT_Ciphertext, const vector<bool> &KEY){
    //子密钥生成
    Build_En_Sub_key(KEY);
    //初始置换
    vector<bool> IP_text = IP(IN_Plaintext);
    //li,ri
    vector<bool> Li(IP_text.begin(), IP_text.begin() + IP_text.size() / 2);
    vector<bool> Ri(IP_text.begin() + IP_text.size() / 2, IP_text.end());
    //轮函数16轮迭代
    En_Round_func(Li, Ri);
    vector<bool> merged;
    merged.insert(merged.end(), Ri.begin(),Ri.end());
    merged.insert(merged.end(), Li.begin(), Li.end());
    //合并时注意顺序 Ri,Li
    //初始逆置换
    OUT_Ciphertext = IPR(merged);
}

//生成解密子密钥
void DES::Bulid_De_sub_key(const vector<bool> &key){
    /*
    //去除校验位
    vector<bool> k(key);
    for (int i = 63; i >= 0; i--) {
        if ((i + 1) % 8 == 0) {  // 判断是否为要删除的元素
            k.erase(k.begin() + i);
        }
    }
    */
    //PC1_table 置换
    vector<bool> k_pc1;
    for (int i = 0; i < PC1_table.size();i++){
        k_pc1.push_back(key[PC1_table[i]-1]);
    }
    //裂开C0,D0
    vector<bool> Ci(k_pc1.begin(), k_pc1.begin() + k_pc1.size() / 2);
    vector<bool> Di(k_pc1.begin() + k_pc1.size() / 2 , k_pc1.end());
    //循环左移生成Ci,Di
    for (int i = 0; i < 16;i++){
        //循环左移
        rotate(Ci.begin(), Ci.begin() + Key_move_table[i], Ci.end());          //左移 mid param    bengin()+ 位移数量
        rotate(Di.begin(), Di.begin() + Key_move_table[i], Di.end());          //右移 mid param    end() - 位移数量
        //合并Ci,Di
        vector<bool> merged;
        merged.reserve(Ci.size() + Di.size());
        merged.insert(merged.end(), Ci.begin(), Ci.end());
        merged.insert(merged.end(), Di.begin(), Di.end());
        //PC_2table置换
        vector<bool> K_pc2;
        for (int i = 0; i < 48; i++){
            //cout << "debug in for in "<<i<<"\n";
            K_pc2.push_back(merged[PC2_table[i]-1]);
        }
        //插入每一轮的子密钥
        //法一
        De_sub_key.insert(De_sub_key.end(), {merged});
        /**
         * 法二
         * De_sub_key.push_back(merged);
      
         */
    }
} 

//De_Round func
void DES::De_Round_func(vector<bool> &l,vector<bool> &r){
    for (int i = 15; i >=0; i--)
    {
        //E扩展 32 bit ->48 bit
        vector<bool> E_r = Expansion(r);
        // XOR subkey
        //cout << "time: " << i << '\n';
        vector<bool> XOR;
        for (int j = 0; j < 48; j++)
        {
            XOR.push_back(E_r[j] ^ De_sub_key[i][j]);
            //cout << De_sub_key[i][j] << " ";
        }
        //cout << '\n';
        //S盒 48 bit -> 32 bit
        vector<bool> S_result;
        S_result = S_compression(XOR);
        //P置换
        vector<bool> P_result;
        for (int j = 0; j < S_result.size(); j++)
        {
            P_result.push_back(S_result[P_table[j]-1]);
        }
        //l XOR P_result
        vector<bool> R_next;
        for (int j = 0; j < l.size(); j++)
        {
            R_next.push_back(l[j] ^ P_result[j]);
        }
        l = r;
        r = R_next;
    }
}

//解密
void DES::DES_Decrypt(vector<bool> &OUT_Plaintext, const vector<bool> &IN_Ciphertext, const vector<bool> &KEY){
    //生成解密子密钥
    Bulid_De_sub_key(KEY);
    //IP
    vector<bool> IP_text = IP(IN_Ciphertext);
    //分割
    vector<bool> Li(IP_text.begin(), IP_text.begin() + IP_text.size() / 2);
    vector<bool> Ri(IP_text.begin() + IP_text.size() / 2, IP_text.end());
    //de_round_func
    De_Round_func(Li, Ri);
    vector<bool> merged;
    merged.insert(merged.end(), Ri.begin(),Ri.end());
    merged.insert(merged.end(), Li.begin(), Li.end());
    //合并时注意顺序 Ri,Li
    OUT_Plaintext  = IPR(merged);
}