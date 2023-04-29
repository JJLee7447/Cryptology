#pragma once
/**
 * author: JJLee
 * date: 2023/04/08
 * email: JJlee7447@gmail.com
 * github: https://github.com/JJLee7447
 * 这个是AES加密算法的头文件，包含了AES类的声明，以及一些常量的定义
 * 
 */

#include<iostream>
#include<vector>
#include<string>
#include<algorithm>
using std::cout;
using std::endl;
using std::hex;
using std::string;
using std::vector;

using Cvec_Matrix =const vector<vector<unsigned char>>;
using Cvec = const vector<unsigned char>;
using Vec_Matrix = vector<vector<unsigned char>>;
using Vec = vector<unsigned char>;
/**
 * 密钥 明文 默认 为 16字节格式 
 *  0x32, 0x88, 0x31, 0xe0, 0x43, 0x5a, 0x31, 0x37, 0xf6, 0x30, 0x98, 0x07, 0xa8, 0x8d, 0xa2, 0x34
*/

class AES
{
private:
    //tips unsigened char is like int but only positive
    //unsigned char is 0-255 , char is -128-127
    //int is -2147483648-2147483647
    static Cvec_Matrix sbox;                    //sbox
    static Cvec_Matrix inv_sbox;                //inverse sbox
    static Cvec rcon;                            //round constant
    static Cvec_Matrix mix_col_mat;             //mix column matrix
    static Cvec_Matrix inv_mix_col_mat;         //inverse mix column matrix
    static Cvec_Matrix shift_row_mat;           //shift row matrix
    static Cvec_Matrix inv_shift_row_mat;       //inverse shift row matrix 
    vector<Vec_Matrix> en_round_key;                         //en_round key
    vector<Vec_Matrix> de_round_key;                         //de_round key

    //private functions
    Vec string16_to_Byte16(const string &str);  //将字符串转换为16字节的明文或密钥
    string Byte16_to_string16(Cvec &Byte_16);  //将16字节的明文或密钥转换为字符串
    Vec_Matrix byte16_to_4_4_mat(Cvec &Byte_16);  //将16字节的明文或密钥转换为4*4的16字节矩阵
    Vec Mat_4_4_to_16byte(Cvec_Matrix &mat_4_4);  //将4*4的16字节矩阵转换为16字节的明文或密钥
    Vec G_func(Vec &w, int &round);  //G函数

    void en_sub_xor_key(Vec &w0_, Vec &w1_, Vec &w2_, Vec &w3_, int &round); //en xor sub key
    void de_sub_xor_key(Vec &w0_, Vec &w1_, Vec &w2_, Vec &w3_, int &round); //de xor sub key
    void EnKeyExpansion(Vec_Matrix &key_16byte);  //En key expansion
    void InvKeyExpansion(Vec_Matrix &key_16byte);  //De key expansion

    void AddRoundKey(Vec_Matrix &state, Vec_Matrix &round_key);  //add round key
    void SubBytes(Vec_Matrix &state);  //sub bytes
    void InvSubBytes(Vec_Matrix &state);  //inverse sub bytes
    void ShiftRows(Vec_Matrix &state);  //shift rows
    void InvShiftRows(Vec_Matrix &state);  //inverse shift rows
    void MixColumns(Vec_Matrix &state);  //mix columns
    void InvMixColumns(Vec_Matrix &state);  //inverse mix columns
    unsigned char GF28_mul(unsigned char a, unsigned char b);  //GF(2^8) multiplication

    void EnCipher(Vec_Matrix &state);  //en cipher
    void InvCipher(Vec_Matrix &state);  //de cipher
    void byteEncrypt(Cvec &plain_text, Vec &cipher_text, Cvec &key);  //16 byte encrypt
    void byteDecrypt(Cvec &cipher_text, Vec &plain_text, Cvec &key);  //16 byte decrypt
    vector<string> split_string(string &str);  //split string
    string join_string(vector<string> &str_vec);  //join string

public:
    void Encrypt(string& plain_text_in, vector<Vec>& cipher_text_out, string& key);  //encrypt
    void Decrypt(vector<Vec>& cipher_text_in, string& plain_text_out, string& key);  //decrypt

    
    void get_sub_key(Vec &key);  //get sub key
    void get_de_key(Vec &key);   //get de key
};


