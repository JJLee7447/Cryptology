#include"sha256.h"
#include<iostream>

using std::cout;
using std::endl;
int main()
{
    Ljj::SHA256 sha256;
    std::string s{"干他100天成为区块链程序员，红军大叔带领着我们，fighting!"};

    std::string digest(sha256(s));
    cout<<s<<"\n"<<digest<<endl;
    return 0;
}
