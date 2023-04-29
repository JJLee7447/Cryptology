#include"AES.h"

/**
 * @brief Construct a new AES::AES object
 * 
*/

// sbox
Cvec_Matrix AES::sbox = {    
    {0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76},
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
    {0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16}};

//inverse sbox
Cvec_Matrix AES::inv_sbox = {
    {0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB},
    {0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB},
    {0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E},
    {0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25},
    {0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92},
    {0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84},
    {0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06},
    {0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B},
    {0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73},
    {0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E},
    {0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B},
    {0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4},
    {0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F},
    {0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF},
    {0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61},
    {0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D}};

// Rcon is a  array of bytes used in the key expansion.
Cvec AES::rcon = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36};
//Mix_col_matrix is a 2D array of bytes used in MixColumns and InvMixColumns.
Cvec_Matrix AES::mix_col_mat = {
    {0x02, 0x03, 0x01, 0x01},
    {0x01, 0x02, 0x03, 0x01},
    {0x01, 0x01, 0x02, 0x03},
    {0x03, 0x01, 0x01, 0x02}};

//Inv_mix_col_matrix is a 2D array of bytes used in MixColumns and InvMixColumns.
Cvec_Matrix AES::inv_mix_col_mat = {
    {0x0E, 0x0B, 0x0D, 0x09},
    {0x09, 0x0E, 0x0B, 0x0D},
    {0x0D, 0x09, 0x0E, 0x0B},
    {0x0B, 0x0D, 0x09, 0x0E}};

//string16_to_byte16将16字节的明文或密钥转换为16字节的明文或密钥
Vec AES::string16_to_Byte16(const string &str){
    vector<unsigned char> result;
    vector<char> tempchar;
    vector<unsigned int> tempint;
    for (int i = 0; i < str.size(); i++){
        tempchar.push_back(str[i]);
    }
    for (int i = 0; i < tempchar.size(); i++){
        tempint.push_back((unsigned int)tempchar[i]);
    }
    for (int i = 0; i < tempint.size(); i++){
        result.push_back(tempint[i]);
    }
    return result;
}
//byte16_to_string16将16字节的明文或密钥转换为16字节的明文或密钥
string AES::Byte16_to_string16(const Vec &Byte_16){
    string str;
        for(unsigned char c : Byte_16){
        str.push_back(static_cast<char>(c));
    }
    return str;
}

//将16字节的明文或密钥转换为4*4的16字节矩阵 
Vec_Matrix AES::byte16_to_4_4_mat(Cvec& Byte_16){
    Vec_Matrix mat(4, Vec(4, 0));
    for (int i = 0; i < 4; i++){
        for(int j = 0; j < 4; j++){
            mat[i][j] = Byte_16[i + j * 4];
        }
    }
    return mat;
}
//将4*4的16字节矩阵转换为16字节的明文或密钥
Vec AES::Mat_4_4_to_16byte(Cvec_Matrix& mat_4_4){
    Vec Byte_16(16, 0);
    for (int i = 0; i < 4; i++){
        for(int j = 0; j < 4; j++){
            Byte_16[i + j * 4] = mat_4_4[i][j];
        }
    }
    return Byte_16;
}

//G fuction
Vec AES::G_func(Vec &w_, int &round){
    Vec w(w_);
    //shift rows
    unsigned char temp = w[0];
    w[0] = w[1];
    w[1] = w[2];
    w[2] = w[3];
    w[3] = temp;
    //sub bytes
    w[0] = sbox[w[0] >> 4][w[0] & 0x0f];
    w[1] = sbox[w[1] >> 4][w[1] & 0x0f];
    w[2] = sbox[w[2] >> 4][w[2] & 0x0f];
    w[3] = sbox[w[3] >> 4][w[3] & 0x0f];
    //xor rcon  字节异或
    w[0] = w[0] ^ rcon[round];
    return w;
}
//en_sub_xor_key
void AES::en_sub_xor_key(Vec &w0,Vec &w1,Vec &w2,Vec &w3,int &round){
    w3 = G_func(w3, round);
    for (int i = 0; i < 4; i++){
        w0[i] = w0[i] ^ w3[i];
        w1[i] = w1[i] ^ w0[i];
        w2[i] = w2[i] ^ w1[i];
        w3[i] = w3[i] ^ w2[i];
    }
    Vec_Matrix mat;
    mat.push_back(w0);
    mat.push_back(w1);
    mat.push_back(w2);
    mat.push_back(w3);
    en_round_key.push_back(mat);

}
//de_sub_xor_key
void AES::de_sub_xor_key(Vec &w0,Vec &w1,Vec &w2,Vec &w3,int &round){
    w3 = G_func(w3, round);
    for (int i = 0; i < 4; i++){
        w0[i] = w0[i] ^ w3[i];
        w1[i] = w1[i] ^ w0[i];
        w2[i] = w2[i] ^ w1[i];
        w3[i] = w3[i] ^ w2[i];
    }
    Vec_Matrix mat;
    mat.push_back(w0);
    mat.push_back(w1);
    mat.push_back(w2);
    mat.push_back(w3);
    de_round_key.push_back(mat);
}

//en key expansion
void AES::EnKeyExpansion(Vec_Matrix &key_16byte){
    //
    Vec w0,w1,w2,w3;
    for(int i = 0; i < 4; i++){
        w0.push_back(key_16byte[0][i]);
        w1.push_back(key_16byte[1][i]);
        w2.push_back(key_16byte[2][i]);
        w3.push_back(key_16byte[3][i]);
    }
    Vec_Matrix mat_0;
    //en_round_key0
    mat_0.push_back(w0); 
    mat_0.push_back(w1); 
    mat_0.push_back(w2); 
    mat_0.push_back(w3);
    en_round_key.push_back(mat_0);
    //en_round_key1-10
    for (int i = 1; i < 11; i++){
        en_sub_xor_key(w0, w1, w2, w3, i);
    }  
}
//inv key expansion
void AES::InvKeyExpansion(Vec_Matrix &key_16byte){
    //
    Vec w0,w1,w2,w3;
    for(int i = 0; i < 4; i++){
        w0.push_back(key_16byte[0][i]);
        w1.push_back(key_16byte[1][i]);
        w2.push_back(key_16byte[2][i]);
        w3.push_back(key_16byte[3][i]);
    }
    Vec_Matrix mat_0;
    //en_round_key0
    mat_0.push_back(w0); 
    mat_0.push_back(w1); 
    mat_0.push_back(w2); 
    mat_0.push_back(w3);
    de_round_key.push_back(mat_0);
    //en_round_key1-10
    for (int i = 1; i < 11; i++){
        de_sub_xor_key(w0, w1, w2, w3, i);
    }  
}
//add round key
void AES::AddRoundKey(Vec_Matrix &state, Vec_Matrix &key){
    for (int i = 0; i < 4; i++){
        for (int j = 0; j < 4; j++){
            state[i][j] = state[i][j] ^ key[i][j];
        }
    }
}
//shift rows
void AES::ShiftRows(Vec_Matrix &state){
    for (int i = 0; i < 4; i++){
        std::rotate(state[i].begin(), state[i].begin() + i, state[i].end());   //使用库函数rotate
    }
}

//Inv_shift rows
void AES::InvShiftRows(Vec_Matrix &state){
    for (int i = 0; i < 4; i++){
        std::rotate(state[i].begin(), state[i].end() - i, state[i].end());   //使用库函数rotate
    }
}

//sub bytes
void AES::SubBytes(Vec_Matrix &state){
    for (int i = 0; i < 4; i++){
        for (int j = 0; j < 4; j++){
            state[i][j] = sbox[state[i][j] >> 4][state[i][j] & 0x0f];  //state 高四位 行  低四位 列
            /**
             * 这行代码的作用是将 AES 状态矩阵 State 中的元素进行 S-Box 替换，具体过程如下：
             * state[i][j] & 0x0f，是将 State 矩阵中第 i 行 j 列元素中的高 4 位清零，并返回低 4 位的值；
             * state[i][j] >> 4，是将 State 矩阵中第 i 行 j 列元素中的低 4 位清零，并返回高 4 位的值；
             * sbox[state[i][j] >> 4][state[i][j] & 0x0f]，是根据 S-Box 表进行替换，将 sbox 中对应位置的值赋给 State 矩阵中第 i 行 j 列元素。
             * 例如，若 State 矩阵中第 i 行 j 列元素值为 0x53，则 state[i][j] >> 4 的结果为 0x05，state[i][j] & 0x0f 的结果为 0x03。
             * 然后，sbox[0x05][0x03] 的值将被赋给 State 矩阵中第 i 行 j 列元素。
             * S-Box 替换是 AES 算法中的一个重要步骤，通过查表将每个字节替换为另一个字节，提高加密的强度。
             * S-Box 表在 AES 算法中通常是一个 16×16 的矩阵，该矩阵中预先存储了 256 个字节的替换值。
             * 在实现 AES 算法时，需要对状态矩阵 State 中的元素进行 S-Box 替换。该行代码就是对 State 矩阵中的元素进行 S-Box 替换的一个实现。
            */
        }
    }
}
//Inv_sub bytes
void AES::InvSubBytes(Vec_Matrix &state){
    for (int i = 0; i < 4; i++){
        for (int j = 0; j < 4; j++){
            state[i][j] = inv_sbox[state[i][j] >> 4][state[i][j] & 0x0f];  //state 高四位 行  低四位 列
        }
    }
}
//GF28 mul
unsigned char AES::GF28_mul(unsigned char a, unsigned char b){  //a 是state 矩阵中的元素，b 是 左乘矩阵中的元素
    unsigned char p = 0;
    unsigned char hi_bit_set;
    for (int counter = 0; counter < 8; counter++) {
        if ((b & 1) == 1)          //b的最低位为1
            p ^= a;                //p = p ^ a 等价 p = a
        hi_bit_set = (a & 0x80);   //a的最高位
        a <<= 1;                   //a 左移一位
        if (hi_bit_set == 0x80)    //a的最高位为1
            a ^= 0x1b; /* x^8 + x^4 + x^3 + x + 1 */
        b >>= 1;
    }
    return p;
}

//mix columns
void AES::MixColumns(Vec_Matrix &state){
    Vec_Matrix state_temp = state;
    for (int i = 0; i < 4; i++){
        state[0][i] = GF28_mul(0x02, state_temp[0][i]) ^ GF28_mul(0x03, state_temp[1][i]) ^ state_temp[2][i] ^ state_temp[3][i];  //这里的GF28_mul是GF(2^8)上的乘法 结果式
        state[1][i] = state_temp[0][i] ^ GF28_mul(0x02, state_temp[1][i]) ^ GF28_mul(0x03, state_temp[2][i]) ^ state_temp[3][i];
        state[2][i] = state_temp[0][i] ^ state_temp[1][i] ^ GF28_mul(0x02, state_temp[2][i]) ^ GF28_mul(0x03, state_temp[3][i]);
        state[3][i] = GF28_mul(0x03, state_temp[0][i]) ^ state_temp[1][i] ^ state_temp[2][i] ^ GF28_mul(0x02, state_temp[3][i]);
    }
}

//Inv_mix columns
void AES::InvMixColumns(Vec_Matrix &state){
    Vec_Matrix state_temp = state;
    for (int i = 0; i < 4; i++){
        state[0][i] = GF28_mul(0x0e, state_temp[0][i]) ^ GF28_mul(0x0b, state_temp[1][i]) ^ GF28_mul(0x0d, state_temp[2][i]) ^ GF28_mul(0x09, state_temp[3][i]);
        state[1][i] = GF28_mul(0x09, state_temp[0][i]) ^ GF28_mul(0x0e, state_temp[1][i]) ^ GF28_mul(0x0b, state_temp[2][i]) ^ GF28_mul(0x0d, state_temp[3][i]);
        state[2][i] = GF28_mul(0x0d, state_temp[0][i]) ^ GF28_mul(0x09, state_temp[1][i]) ^ GF28_mul(0x0e, state_temp[2][i]) ^ GF28_mul(0x0b, state_temp[3][i]);
        state[3][i] = GF28_mul(0x0b, state_temp[0][i]) ^ GF28_mul(0x0d, state_temp[1][i]) ^ GF28_mul(0x09, state_temp[2][i]) ^ GF28_mul(0x0e, state_temp[3][i]);
    }
}

// en cipher
void AES::EnCipher(Vec_Matrix &state){
    AddRoundKey(state, en_round_key[0]);
    for (int i = 1; i < 10; i++){
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, en_round_key[i]);
    }
    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, en_round_key[10]);
}

// de cipher
void AES::InvCipher(Vec_Matrix &state){
    AddRoundKey(state, de_round_key[10]);
    for (int i = 9; i >= 1; i--){
        InvShiftRows(state);
        InvSubBytes(state);
        AddRoundKey(state, de_round_key[i]);
        InvMixColumns(state);
    }
    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(state, de_round_key[0]);
}

//split string to 16 byte
vector<string> AES::split_string(string &str){
    vector<string> result;
    int len = str.length();
    int pos = 0;
    while (pos < len){
        string group = str.substr(pos, 16);
        if (group.length() < 16){
            group.append(16 - group.length(), ' ');
        }
        result.push_back(group);
        pos += 16;
    }
    return result;
}

//join string
string AES::join_string(vector<string> &str_vec){
    string result;
    for (int i = 0; i < str_vec.size(); i++){
        result.append(str_vec[i]);
    }
    return result;
}

// 固定字节长度为16加密解密
void AES::byteEncrypt(Cvec &plain_text, Vec &cipher_text, Cvec &key){
    Vec_Matrix plain_text_16byte = byte16_to_4_4_mat(plain_text);
    Vec_Matrix key_16byte = byte16_to_4_4_mat(key);
    EnKeyExpansion(key_16byte);
    EnCipher(plain_text_16byte);
    cipher_text = Mat_4_4_to_16byte(plain_text_16byte);
}

void AES::byteDecrypt(Cvec &cipher_text, Vec &plain_text, Cvec &key){

    Vec_Matrix cipher_text_16byte = byte16_to_4_4_mat(cipher_text);

    Vec_Matrix key_16byte = byte16_to_4_4_mat(key);

    InvKeyExpansion(key_16byte);

    InvCipher(cipher_text_16byte);
    plain_text = Mat_4_4_to_16byte(cipher_text_16byte);
}

//测试接口
void AES::get_sub_key(Vec &key){
    Vec_Matrix key_16byte = byte16_to_4_4_mat(key);
    EnKeyExpansion(key_16byte);
    vector<Vec_Matrix> mat = en_round_key;
    for (int i = 0; i < mat.size(); i++)
    {
        for (int j = 0; j < mat[i].size(); j++)
        {
            for (int k = 0;k < mat[i][j].size();k++)
            {
                std::cout << hex << (int)mat[i][j][k] << " ";
            }
            cout<<endl; 
        }
        cout<<"-----------------"<<endl;
        
    }   
}
void AES::get_de_key(Vec &key) {
    Vec_Matrix key_16byte = byte16_to_4_4_mat(key);
    InvKeyExpansion(key_16byte);
    vector<Vec_Matrix> mat = de_round_key;
    for (int i = 0; i < mat.size(); i++)
    {
        for (int j = 0; j < mat[i].size(); j++)
        {
            for (int k = 0;k < mat[i][j].size();k++)
            {
                std::cout << hex << (int)mat[i][j][k] << " ";
            }
            cout<<endl; 
        }
        cout<<"-----------------"<<endl;
    }
}


//接口函数
void AES::Encrypt(string& plain_text_in, vector<Vec>& cipher_text_out, string& key){
    //将明文分割为16字节的字符串
    vector<string> plain_text_vec = split_string(plain_text_in);
    int len = plain_text_vec.size();
    //初始化密文为 16*len 的0矩阵
    vector<Vec> cipher_text_vec(len, Vec(16, 0));
    //将密钥转换为16字节的字符串
    Vec key_vec(string16_to_Byte16(key));
    //对每个16字节的字符串进行加密
    for (int i = 0; i < plain_text_vec.size(); i++)
    {
        Vec plain_text(string16_to_Byte16(plain_text_vec[i]));
        byteEncrypt(plain_text, cipher_text_vec[i], key_vec);
    }
    //返回密文矩阵
    cipher_text_out = cipher_text_vec;
}

void AES::Decrypt(vector<Vec>& cipher_text_in, string& plain_text_out, string& key){
    //将密钥转换为16字节的字符串
    Vec key_vec(string16_to_Byte16(key));
    //16字节的字符串数组 
    vector<string> plain_text_vec;
    //16字节的字符串 用于存储解密后的明文块
    string temp;
    //对每个16字节的字符串进行解密
    for (int i = 0; i < cipher_text_in.size(); i++)
    {
        //解密后的明文块
        Vec plain_text;
        //解密
        byteDecrypt(cipher_text_in[i],plain_text, key_vec);
        //将明文块转换为字符串
        temp = Byte16_to_string16(plain_text);
        //将明文块添加到明文数组中
        plain_text_vec.push_back(temp);
    }
    //将明文数组拼接为字符串
    plain_text_out = join_string(plain_text_vec);
    
}