#ifndef DES_H_
#define DES_H_

#include <bitset>
#include<string>
#include<vector>
#include<iostream>
#include <utility>
#include <sstream>


namespace encryption
{
  class DES
  {
    public:
      DES(std::bitset<9> key):
        key_(key)
      {
        getKey();
      };
      
      ~DES() = default;
      
      std::string Encrypt (std::string cipherText);
      std::string Decrypt (std::string cipherText);
    private:
   
      std::vector<std::bitset<8>> key_round_;
      std::bitset<9> key_;
      void getKey ();
      std::bitset<8> ExpandText(std::bitset<6> text);
      
      std::bitset<6> SBoxes(std::bitset<8> sBox);
      
      std::bitset<12> DecryptUtil(std::bitset<12> text, int round);
      std::bitset<12> EncryptUtil(std::bitset<12> text, int round);
  };
}


#endif /* DES_H_ */
