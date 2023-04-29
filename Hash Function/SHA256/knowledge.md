


给出一个 `unsigned short` 类型（占2Byte）的整数，将其高8位与低8位互换，并输出互换后的数。例如：25（十进制） = 0000 0000 0001 1001；
互换后得到6400 = 0001 1001 0000 0000 = 212 + 211 + 28。那么该如何用程序实现呢？就以循环左移k位为例。计算机的实现需要两个步骤：

* 将正整数a先左移k位
* 再将正整数a右移n-k位（n是正整数共占的位数）
* 将上述两步得到的数进行与操作，便得到了最后的结果。


```cpp
    inline uint32_t Rotr(uint32_t x, uint32_t n){  //循环右移
        return (x >> n) | (x << (32 - n));
    }
    inline uint32_t Shr(uint32_t x, uint32_t n){    //右移
        return x >> n;
    }
```

`std::string` to `int`
```cpp
std::string s{"hello world"};
std::vector v(s.begin().s.end());
for(auto i:vector){
    std::cout << i << std::endl; 
}
```
65 66 67 32 97 98 99