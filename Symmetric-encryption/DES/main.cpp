#include "DES.h"
#include<iostream>

void func(const int & a){
    std::cout << a << " ";
}


int main()
{   
    /*
    vector<bool> plaintext_in(64, (bool)0);
    
    for (int i = 0; i < 64; i+=4)
    {
        plaintext_in[i] = (bool)1;
    }
    cout << "plain text IN:\n";
    for (bool i :plaintext_in){
        cout << i << " ";
    }
    cout << '\n';

    vector<bool> key(64, (bool)0);
    for (int i = 0; i < 64; i+=8)
    {
        key[i] = (bool)1;
    }
    vector<bool> ciphertext_out;
    vector<bool> plaintext_out;
    DES a;
    a.DES_Encrypt(plaintext_in, ciphertext_out, key);
    a.DES_Decrypt(plaintext_out, ciphertext_out, key);
    cout << "plain text out:\n";
    for (bool i: plaintext_out)
    {
        cout << i << " ";
    }
    */
   // 密钥
    vector<bool> key(64, (bool)0);
    for (int i = 0; i < 64; i+=8)
    {
        key[i] = (bool)1;
    }

    vector<bool> key_(64, (bool)0);
    for (int i = 0; i < 64; i+=4)
    {
        key[i] = (bool)1;
    }
    // 明文
    string str{"hliaffd"};
    string b;
    // 密文
    vector<bool> encrypt;
    // 明文
    vector<bool> plain_in,plain_out;

    DES a;
    plain_in = a.bit8_String_To_bit64_VectorBool(str);
    a.DES_Encrypt(plain_in, encrypt, key);
    a.DES_Decrypt(plain_out, encrypt, key_);
    b = a.bit64_VectorBool_To_bit8_String(plain_out);
    cout << b;
}
