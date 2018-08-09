#include "des.h"

namespace encryption
{
  constexpr char s1[2][8] = 
  {
    {0x5, 0x2, 0x1, 0x6, 0x3, 0x4, 0x7, 0},
    {0x1, 0x4, 0x6, 0x2, 0x0, 0x7, 0x5, 0x3}
  };

  constexpr char s2[2][8] = 
  {
    {0x4, 0x0, 0x6, 0x5, 0x7, 0x1, 0x3, 0x2},
    {0x5, 0x3, 0x0, 0x7, 0x6, 0x2, 0x1, 0x4}
  };

  void DES::getKey()
  {
    for (int round = 0; round < 9; round++)
    {
      std::bitset<8> key;
      for (int i = 0; i < 8; i++)
      {
        key[i] = key_[round % 9];
      }
      key_round_.push_back(key);
    } 
  }

  std::bitset<8> DES::ExpandText(std::bitset<6> text)
  {
    std::bitset<8> exText;
    exText[0] = text[0]; exText[1] = text[1]; 
    exText[2] = text[3]; exText[3] = text[2];
    exText[4] = text[3]; exText[5] = text[2];
    exText[6] = text[4]; exText[7] = text[5];
    
    return exText;
  }

  std::bitset<6> DES::SBoxes(std::bitset<8> sBox)
  {
    std::bitset<6> sBox_output;
    sBox_output.reset();
    sBox_output = 
      std::bitset<6>(s1[sBox[3]][(int)sBox.to_ulong() & 0x7]);
    sBox_output = 
      std::bitset<6>(sBox_output.to_ulong() | ((s2[sBox[7]][((int)sBox.to_ulong() & 0x70) >> 4]) << 3));
    return sBox_output;  
  }
  
  std::bitset<12> DES::EncryptUtil(std::bitset<12> text, int round)
  {
     //std::cout <<"++++" << text.to_string() << std::endl;
     if (round == 9)
        return text;
     std::bitset<6> left_i_1 = 
        std::bitset<6>((text.to_ulong() & 0xFC0) >> 6);
     std::bitset<6> right_i_1 = std::bitset<6>(text.to_ulong() & 0X3F);
     std::bitset<8> ex = ExpandText(right_i_1);
     ex ^= key_round_[round];
     std::bitset<6> right_i = SBoxes(ex);
     right_i ^= left_i_1;
     round = round + 1; 
     std::bitset<12> encrypt_text = 
        std::bitset<12>((right_i_1.to_ulong() << 6) | right_i.to_ulong());
      //std::cout << "-------" << encrypt_text.to_string() << std::endl;
      return (EncryptUtil(encrypt_text, round));
  }

  std::string DES::Encrypt (std::string cipherText)
  {
    std::pair<bool, std::bitset<4>> remainder(false,0);
    std::string output;
    for (int i = cipherText.length() - 1; i >= 0; i--)
    {
      std::bitset<12> text(0);
      if (remainder.first == true)
      {
        text = std::bitset<12> (remainder.second.to_ulong() << 8);
        remainder = std::make_pair(false, 0);
        std::cout << cipherText[i] <<" " << i << std::endl;
        text = std::bitset<12>(text.to_ulong() | cipherText[i]);
      }
      else
      {
        text = std::bitset<12> (cipherText[i] << 4);
        i--;
        text = std::bitset<12>(text.to_ulong() | 
          ((cipherText[i] & 0xF0) >> 4));
        remainder = std::make_pair(true, cipherText[i] & 0xF);
      }
      std::ostringstream ss;
      ss << ((EncryptUtil(text, 0).to_ulong()) & 0x3FF);
      output += ss.str();
    }  
    std::cout << output << std::endl;
    return output;
  } 

   std::bitset<12> DES::DecryptUtil(std::bitset<12> text, int round)
  {
     //std::cout <<"++++" << text.to_string() << std::endl;
     if (round == -1)
        return text;
     std::bitset<6> left_i_1 = 
        std::bitset<6>((text.to_ulong() & 0xFC0) >> 6);
     std::bitset<6> right_i_1 = std::bitset<6>(text.to_ulong() & 0X3F);
     std::bitset<8> ex = ExpandText(right_i_1);
     ex ^= key_round_[round];
     std::bitset<6> right_i = SBoxes(ex);
     right_i ^= left_i_1;
     round = round - 1; 
     std::bitset<12> encrypt_text = 
        std::bitset<12>((right_i_1.to_ulong() << 6) | right_i.to_ulong());
      //std::cout << "-------" << encrypt_text.to_string() << std::endl;
      return (DecryptUtil(encrypt_text, round));
  }

  std::string DES::Decrypt (std::string cipherText)
  {
    std::pair<bool, std::bitset<4>> remainder(false,0);
    std::string output;
    for (int i = cipherText.length() - 1; i >= 0; i--)
    {
      std::bitset<12> text(0);
      if (remainder.first == true)
      {
        text = std::bitset<12> (remainder.second.to_ulong() << 8);
        remainder = std::make_pair(false, 0);
        std::cout << cipherText[i] <<" " << i << std::endl;
        text = std::bitset<12>(text.to_ulong() | cipherText[i]);
      }
      else
      {
        text = std::bitset<12> (cipherText[i] << 4);
        i--;
        text = std::bitset<12>(text.to_ulong() | 
          ((cipherText[i] & 0xF0) >> 4));
        remainder = std::make_pair(true, cipherText[i] & 0xF);
      }
      output += DecryptUtil(text, 8).to_string();
    }  
    std::cout << output << std::endl;
    return output;
  }
}
