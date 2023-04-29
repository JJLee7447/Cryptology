#include"SHA256.h"

// Path: SHA256.h
namespace Ljj{

// 初始化哈希值
const std::vector<uint32_t> SHA256::initial_hash_values{
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19
};
// 64常量
const std::vector<uint32_t> SHA256::constants{
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

/**
 * @brief 预处理
 * @param[in] message: 输入信息 类型 std::vector<uint8_t>
*/
void SHA256::preprocessing (std::vector<uint8_t> &message)const
{
    /**
     * STEP1：附加填充比特
     * 在报文末尾进行填充，使报文长度在对512取模以后的余数是448
     * 填充是这样进行的：先补第一个比特为1，然后都补0，直到长度满足对512取模后余数是448。
     * *需要注意的是，信息必须进行填充，也就是说，即使长度已经满足对512取模后余数是448，补位也必须要进行，这时要填充512个比特。
     * *因此，填充是至少补一位，最多补512位。
    */
    const auto original_bit_length = message.size()*8;
    auto remainder = message.size() % 64;
    auto original_length = message.size();
    if(remainder < 56){
        message.resize(message.size()+56-remainder,0x00);
        message[original_length] = 0x80;
    }
    else if(remainder == 56){
        message.resize(message.size() + 64,0x00);
        message[original_length] = 0x80;
    }
    else{
        message.resize(message.size() + 64 - remainder + 56,0x00);
        message[original_length] = 0x80;
    }
    //STEP2：附加长度  附加长度值就是将原始数据（第一步填充前的消息）的长度信息补到已经进行了填充操作的消息后面。
    //append length of message (before pre-processing), in bits, as 64-bit big-endian integer
    // x86 使用小端序
    for (int i = 1; i <= 8; i++)
    {
        message.emplace_back((static_cast<uint8_t>(original_bit_length >> (64 - i * 8))));
    }
    /**
     * 在SHA-256算法中，附加长度值时使用的是大端序。需要注意的是，填充操作中使用的是与平台相关的字节序，比如在x86平台上使用的是小端序 (little-endian)。
    */ 
}

std::vector<std::vector<uint8_t>> SHA256::message_blocks(const std::vector<uint8_t> &message)const
{
    if(message.size() % 64 != 0){
        std::ostringstream os;
        os << "message is not padded to 512 bits  and invalid message size: " << message.size();
        throw std::invalid_argument(os.str());
    }

    std::vector<std::vector<uint8_t>> blocks;
    for (size_t i = 0; i < message.size(); i += 64)
    {
        blocks.emplace_back(message.begin() + i, message.begin() + i + 64);
    }
    return blocks;
}

std::vector<uint32_t> SHA256::create_word_blocks(const std::vector<uint8_t> &message_block)const
{
    if(64 != message_block.size()){
        std::ostringstream os;
        os << "invalid message size: " << message_block.size();
        throw std::invalid_argument(os.str());
    }
    std::vector<uint32_t> words(64);
    for (int i = 0; i < 16; i++){
        words[i] = (static_cast<uint32_t>(message_block[i * 4]) << 24) |
                   (static_cast<uint32_t>(message_block[i * 4 + 1]) << 16) |
                   (static_cast<uint32_t>(message_block[i * 4 + 2]) << 8) |
                   (static_cast<uint32_t>(message_block[i * 4 + 3]));
    }

    for (size_t i = 16; i < 64; i++){
        words[i] = Small_Sig1(words[i - 2]) + words[i - 7] + Small_Sig0(words[i - 15]) + words[i - 16];     // const 成员函数作用于 const 对象  非 const 成员函数不能作用于 const 对象
    }
    return words;
}

void SHA256::process_message_block(const std::vector<uint32_t> &word_blocks , std::vector<uint32_t> &message_digest) const{
    if(8 != message_digest.size() || 64 != word_blocks.size()){
        std::ostringstream os;
        os << "invalid message digest size: " << message_digest.size()<< " or invalid word blocks size: " << word_blocks.size();
        throw std::invalid_argument(os.str());
    }
    auto digest = message_digest;
    for (int i = 0; i < 64; i++){
        uint32_t temp1 = digest[7] + Big_Sig1(digest[4]) + Ch(digest[4], digest[5], digest[6]) + constants[i] + word_blocks[i];
        uint32_t temp2 = Big_Sig0(digest[0]) + Maj(digest[0], digest[1], digest[2]);
        digest[7] = digest[6];
        digest[6] = digest[5];
        digest[5] = digest[4];
        digest[4] = digest[3] + temp1;
        digest[3] = digest[2];
        digest[2] = digest[1];
        digest[1] = digest[0];
        digest[0] = temp1 + temp2;
    }
    for (int i = 0; i < 8; i++){
        message_digest[i] += digest[i];
    }
}

std::vector<uint8_t> SHA256::bit_32_to_bit_8(const std::vector<uint32_t> &input)const{
    std::vector<uint8_t> output;
    for (auto it = input.begin();it!=input.end();it++){
        for (int i = 0; i < 4; i++){
            output.emplace_back(static_cast<uint8_t>(*it >> (24 - i * 8)));
        }
        
    }    
    return output;
}

std::vector<uint8_t> SHA256::encrypt( std::vector<uint8_t> message) const{
    //文本处理
    preprocessing(message);
    //分块
    auto message_blocks = this->message_blocks(message);
    //分块处理
    std::vector<uint32_t> message_digest(initial_hash_values);
    for(const auto &block : message_blocks){
        process_message_block(create_word_blocks(block), message_digest);
    }
    //输出
    return bit_32_to_bit_8(message_digest);
}







// 对象函数接口
std::string SHA256::operator()(const std::string &message) const
{   
    auto digest = encrypt(std::vector<uint8_t>(message.begin(), message.end()));
    std::ostringstream os;
    for (auto i : digest){
        os << std::hex << std::setfill('0') << std::setw(2) << static_cast<unsigned short>(i);
    }
    return os.str();
}




}// namespace Ljj