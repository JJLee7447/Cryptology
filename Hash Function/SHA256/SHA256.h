/**
 * @file SHA256.h
 * @brief SHA256 class declaration
 * @author JJLee
 * @version 1.0
 * @date 2023-05-01
 * 
*/
/**
 * SHA256 加密流程
 * 1. 预处理
 * 2. 填充
 * 3. 初始化哈希值
 * 4. 循环处理每个分组
 * 5. 输出 
 * uint8_t 8位无符号整数     1byte
 * uint16_t 16位无符号整数 
 * uint32_t 32位无符号整数   4byte
 * 
*/



#ifndef SHA256_H
#define SHA256_H

#include <iomanip>
#include <sstream>
#include <vector>
#include <string>
#include <cstdint>

namespace Ljj{
class SHA256
{
public:

private:
    static const std::vector<uint32_t> initial_hash_values;  //初始哈希值
    static const std::vector<uint32_t> constants;            //64常量
    

protected:
    inline uint32_t Rotr(uint32_t x, int n)const noexcept{  //循环右移
        return (x >> n) | (x << (32 - n));
    }
    inline uint32_t Shr(uint32_t x, int n)const noexcept{    //右移
        return x >> n;
    }
    /**
     * 6钟逻辑函数
    */
    inline uint32_t Ch(uint32_t x, uint32_t y, uint32_t z)const noexcept{  //选择函数
        return (x & y) ^ ((~x) & z);  
    }
    inline uint32_t Maj(uint32_t x, uint32_t y, uint32_t z)const noexcept{  //主函数
        return (x & y) ^ (x & z) ^ (y & z);
    }
    inline uint32_t Big_Sig0(uint32_t x) const noexcept{
        return Rotr(x, 2) ^ Rotr(x, 13) ^ Rotr(x, 22);
    }
    inline uint32_t Big_Sig1(uint32_t x) const noexcept{
        return Rotr(x, 6) ^ Rotr(x, 11) ^ Rotr(x, 25);
    }
    inline uint32_t Small_Sig0(uint32_t x)const noexcept{
        return Rotr(x, 7) ^ Rotr(x, 18) ^ Shr(x, 3);
    }
    inline uint32_t Small_Sig1(uint32_t x)const noexcept{
        return Rotr(x, 17) ^ Rotr(x, 19) ^ Shr(x, 10);
    }
    
    /**
     * @brief: 预处理函数
     * @param[in] message: 输入信息
     * @param[out] message: 预处理后的信息
    */
    void preprocessing (std::vector<uint8_t> &message)const;  //处理输入信息

    /**
     * @brief: message 将消息分解成64-byte大小的块
     * @param[in] message: 输入信息
     * @return std::vector<std::vector<uint8_t>>: 分组后的信息
    */
    std::vector<std::vector<uint8_t>> message_blocks(const std::vector<uint8_t> &message)const;

    /**
     * @brief: 将64-byte大小的块分成64个32-bit 即 4-byte大小的字
     * @param[in] message_block: 输入信息
     * @return std::vector<uint32_t>: 64字
    */
    std::vector<uint32_t> create_word_blocks(const std::vector<uint8_t> &message_block)const;

    /**
     * @brief: 基于64字的消息块，进行64轮的处理
     * @param[in] word_blocks: 64字
     * @param[in][out] message_digest: 哈希值
    */
    void process_message_block(const std::vector<uint32_t> &word_blocks, std::vector<uint32_t> &message_digest)const;

    /**
     * @brief: 将哈希值转换成字符串
     * @param[in] message_digest: 哈希值
     * @return: 步长 8-bit哈希值
    */
    std::vector<uint8_t> bit_32_to_bit_8(const std::vector<uint32_t> &message_digest)const;

    /**
     * @brief: encrypt
     * @param[in] message: 输入信息
     * @return: 步长 8-bit哈希值
    */
    std::vector<uint8_t> encrypt(std::vector<uint8_t> message)const;
public:
    /**
     * @brief: SHA256算法对输入信息进行处理，得到哈希值
     * @param[in] message: 输入信息
     * @param[out] hash_values: 哈希值
    */
    std::string operator()(const std::string &message) const;
};
    

    
}

#endif // SHA256_H